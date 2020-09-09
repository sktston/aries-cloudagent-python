"""Multi wallet handler implementation of BaseWallet interface."""

import json
import re
import time
import uuid

import indy.anoncreds
import indy.did
import indy.crypto
import hashlib
from indy.error import IndyError, ErrorCode
from base64 import b64encode, b64decode

from ..config.wallet import WALLET_CONFIG_RECORD_TYPE
from ..storage.error import StorageNotFoundError
from ..storage.record import StorageRecord
from ..wallet.base import BaseWallet
from ..storage.base import BaseStorage
from ..ledger.base import BaseLedger
from ..wallet.error import WalletError, WalletDuplicateError
from ..wallet.plugin import load_postgres_plugin
from ..utils.classloader import ClassLoader
from ..config.provider import DynamicProvider
from ..config.injection_context import InjectionContext
from ..connections.models.connection_record import (
    ConnectionRecord,
)

from .error import KeyNotFoundError, WalletAccessError
from .error import WalletNotFoundError
from .error import DuplicateMappingError


class WalletHandler():
    """Class to handle multiple wallets."""

    WALLET_CLASSES = {
        "basic": "aries_cloudagent.wallet.basic.BasicWallet",
        "indy": "aries_cloudagent.wallet.indy.IndyWallet",
    }
    DEFAULT_KEY = ""
    DEFAULT_KEY_DERIVIATION = "ARGON2I_MOD"
    DEFAULT_NAME = "default"
    DEFAULT_STORAGE_TYPE = None
    DEFAULT_WALLET_CLASS = "aries_cloudagent.wallet.indy.IndyWallet"
    DEFAULT_STORAGE_CLASS = "aries_cloudagent.storage.indy.IndyStorage"
    DEFAULT_LEDGER_CLASS = "aries_cloudagent.ledger.indy.IndyLedger"
    DEFAULT_AUTO_ADD = True

    KEY_DERIVATION_RAW = "RAW"
    KEY_DERIVATION_ARGON2I_INT = "ARGON2I_INT"
    KEY_DERIVATION_ARGON2I_MOD = "ARGON2I_MOD"

    def __init__(self, provider: DynamicProvider, config: dict = None):
        """Initilaize the handler."""
        self._auto_create = config.get("auto_create", True)
        self._auto_remove = config.get("auto_remove", False)
        self._freshness_time = config.get("freshness_time", False)
        self._key = config.get("key") or self.DEFAULT_KEY
        self._key_derivation_method = (
            config.get("key_derivation_method") or self.DEFAULT_KEY_DERIVIATION
        )
        self._storage_type = config.get("storage_type") or self.DEFAULT_STORAGE_TYPE
        self._storage_config = config.get("storage_config", None)
        self._storage_creds = config.get("storage_creds", None)
        self._master_secret_id = None
        self._wallet_class = config.get("wallet_class") or self.DEFAULT_WALLET_CLASS
        if self._wallet_class == self.DEFAULT_WALLET_CLASS:
            self.WALLET_TYPE = "indy"
        else:
            raise WalletError("Wallet handler only works with indy wallet.")
        self._auto_add = config.get("auto_add") or self.DEFAULT_AUTO_ADD

        if self._storage_type == "postgres_storage":
            load_postgres_plugin(self._storage_config, self._storage_creds)

        # Maps: `inbound path` -> `wallet`
        self._path_mappings = {}
        # Maps: `verkey` -> `wallet`
        self._handled_keys = {}
        # Maps: `connection_id` -> `wallet`
        self._connections = {}

        self._provider = provider

    async def get_instances(self):
        """Return list of handled instances."""
        return list(self._provider._instances.keys())

    async def add_instance(self, config: dict, context: InjectionContext):
        """
        Add a new instance to the handler to be used during runtime.

        Args:
            config: Settings for the new instance.
            context: Injection context.
        """
        wallet_type = config['type'] or self.DEFAULT_WALLET_CLASS
        wallet_class = self.WALLET_CLASSES[wallet_type]

        if config["name"] in self._provider._instances.keys():
            raise WalletDuplicateError()

        wallet = ClassLoader.load_class(wallet_class)(config)
        await wallet.open()
        storage = ClassLoader.load_class(self.DEFAULT_STORAGE_CLASS)(wallet)
        ledger = ClassLoader.load_class(self.DEFAULT_LEDGER_CLASS)("default", wallet)

        # Store wallet in wallet provider.
        # FIXME: might be possible  to handle cleaner?
        # FIXME: Delete storage and ledger if wallet is closed, is it possible to reopen?
        # FIXME: What  about `holder`, `issuer`, etc?
        self._provider._instances[wallet.name] = wallet
        storage_provider = context.injector._providers[BaseStorage]
        storage_provider._instances[wallet.name] = storage
        ledger_provider = context.injector._providers[BaseLedger]
        ledger_provider._instances[wallet.name] = ledger

        # Get dids and check for paths in metadata.
        dids = await wallet.get_local_dids()
        for did in dids:
            self._handled_keys[did.verkey] = wallet.name
            # Get path matppings of wallet (path, wallet.name).
            if did.metadata.get('path'):
                path = did.metadata['path']
                self.add_path_mapping(
                    wallet.name, path)

        # Without changing the requested instance, the storage provider
        # picks up the correct wallet for fetching the connections.
        adding_context = context.copy()
        adding_context.settings.set_value("wallet.id", wallet.name)

        # Add connections of opened wallet to handler.
        tag_filter = {}
        post_filter = {}
        # wallet_handler.set_instance(config["name"])
        records = await ConnectionRecord.query(adding_context, tag_filter, post_filter)
        connections = [record.serialize() for record in records]
        for connection in connections:
            await self.add_connection(connection["connection_id"], config["name"])

    async def set_instance(self, wallet_name: str, context: InjectionContext):
        """Set a specific wallet to open by the provider."""
        instances = await self.get_instances()
        if wallet_name not in instances:
            # wallet is not opened
            # search wallet in admin storage and open wallet if exist
            admin_context = context.copy()
            admin_context.settings.set_value("wallet.id", context.settings.get_value("wallet.name"))
            record_list = await self.get_wallets(admin_context, {"name": wallet_name})
            if record_list:
                # Should be only 1 record
                for record in record_list:
                    await self.add_instance(json.loads(record.value), admin_context)
            else:
                raise WalletNotFoundError('Requested not existing wallet instance.')
        context.settings.set_value("wallet.id", wallet_name)

    async def delete_instance(self, wallet_name: str):
        """
        Delete handled instance from handler and storage.

        Args:
            wallet_name: Identifier of the instance to be deleted.
        """

        try:
            wallet = self._provider._instances.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"Wallet not found: {wallet_name}")

        if wallet.WALLET_TYPE == 'indy':
            # Delete wallet from storage.
            try:
                await wallet.close()
                await indy.wallet.delete_wallet(
                    config=json.dumps(wallet._wallet_config),
                    credentials=json.dumps(wallet._wallet_access),
                )
            except IndyError as x_indy:
                if x_indy.error_code == ErrorCode.WalletNotFoundError:
                    raise WalletNotFoundError(f"Wallet not found: {wallet_name}")
                raise WalletError(str(x_indy))

        # Remove all path mappings of wallet.
        self._path_mappings = {
            key: val for key, val in self._path_mappings.items() if val != wallet_name
            }
        self._handled_keys = {
            key: val for key, val in self._path_mappings.items() if val != wallet_name
            }
        self._connections = {
            key: val for key, val in self._path_mappings.items() if val != wallet_name
            }

    async def get_wallets(self, context: InjectionContext, query: str = None,):
        """
        Return list of wallets

        Args:
            context: Injection context.
            query: query
        """
        # search wallets in admin storage (admin context is assumed)
        storage: BaseStorage = await context.inject(BaseStorage)
        record_list = await storage.search_records(
            type_filter=WALLET_CONFIG_RECORD_TYPE,
            tag_query=query,
        ).fetch_all()

        return record_list

    async def add_wallet(self, config: dict, context: InjectionContext):
        """
        Add a new wallet

        Args:
            config: Settings for the new instance.
            context: Injection context.
        """
        # Pass default values into config
        config["storage_type"] = self._storage_type
        config["storage_config"] = self._storage_config
        config["storage_creds"] = self._storage_creds

        # add wallet config in admin storage if not exist (admin context is assumed)
        storage: BaseStorage = await context.inject(BaseStorage)
        try:
            result = await storage.search_records(
                type_filter=WALLET_CONFIG_RECORD_TYPE,
                tag_query={"name": config["name"]},
            ).fetch_single()
            if result:
                raise WalletDuplicateError()
        except StorageNotFoundError:
            pass

        record = StorageRecord(
            type=WALLET_CONFIG_RECORD_TYPE,
            value=json.dumps(config),
            tags={"name": config["name"]},
            id=str(uuid.uuid4()),
        )
        await storage.add_record(record)

        # open wallet if not opened
        instances = await self.get_instances()
        if config["name"] not in instances:
            await self.add_instance(config, context)

        return record

    async def remove_wallet(self, wallet_id: str, context: InjectionContext):
        """
        Remove a wallet

        Args:
            wallet_id: Identifier of the instance to be deleted.
            context: Injection context.
        """
        # get record to get wallet name (admin context is assumed)
        storage = await context.inject(BaseStorage)
        try:
            record = await storage.get_record(
                record_type=WALLET_CONFIG_RECORD_TYPE,
                record_id=wallet_id,
            )
        except StorageNotFoundError:
            raise WalletNotFoundError(f"specified wallet_id is not found: {wallet_id}")

        record_dict = json.loads(record.value)
        wallet_name = record_dict["name"]

        # can not delete admin wallet
        if wallet_name == context.settings.get_value("wallet.name"):
            raise WalletAccessError(f"deleting admin wallet is not allowed")

        # remove wallet config in admin storage
        await storage.delete_record(record)

        # close wallet if opened
        instances = await self.get_instances()
        if wallet_name in instances:
            await self.delete_instance(wallet_name)

    async def generate_path_mapping(self, wallet_id: str, did: str = None) -> str:
        """
        Create and store new path mapped to the currently active wallet.

        Args:
            wallet_id: Identifier of the wallet for which a new path mapping
                    shall be generated.
            did: DID for which the path is generated.
            key: [if no did] Key used as random input to generrate path mapping.

        Returns:
            path: path to use as postfix to add to default endpoint

        """
        if did:
            digest = hashlib.sha256(str.encode(did)).digest()
        else:
            t = time.time()
            digest = hashlib.sha256(str.encode(str(t) + wallet_id)).digest()

        id = b64encode(digest).decode()
        # Clear all special characters
        path = re.sub('[^a-zA-Z0-9 \n]', '', id)
        self._path_mappings[path] = wallet_id

        # Store endpoint in did metadata
        # TODO: check for old path in metadata.
        # TODO: Add to metadata if already exist.
        if did:
            wallet = self._provider._instances[wallet_id]
            metadata = {"path": path}
            await wallet.replace_local_did_metadata(did, metadata)

        return path

    def add_path_mapping(self, wallet_id, path):
        """Store a new path mapping.

        Args:
            wallet_id: Identifier of wallet for which to add the new mapping.
            path: Path which shall be mapped to the wallet.

        """
        if path in self._path_mappings.keys():
            raise DuplicateMappingError()
        self._path_mappings[path] = wallet_id

    def get_paths(self, wallet: str) -> []:
        """
        Return all connection handles exposed for the currently active wallet.

        Returns:
            handles: List of connection handles.

        """

        handles = [k for k, v in self._path_mappings.items() if v == wallet]

        return handles

    async def get_wallet_for_msg(self, body: bytes) -> [str]:
        """
        Parses an inbound message for recipient keys and returns the wallets
        associated to keys.

        Args:
            body: Inbound raw message

        Raises:
            KeyNotFoundError: if given key does not belong to handled_keys
        """
        msg = json.loads(body)
        protected = json.loads(b64decode(msg['protected']))
        recipients = protected['recipients']
        wallet_ids = []
        # Check each recipient public key (in `kid`) if agent handles a wallet
        # associated to that key.
        for recipient in recipients:
            kid = recipient['header']['kid']
            try:
                wallet_id = await self.get_wallet_for_key(kid)
            except KeyNotFoundError:
                wallet_id = None
            wallet_ids.append(wallet_id)

        return wallet_ids

    async def get_wallet_for_path(self, path: str) -> str:
        """
        Return the identifier of the wallet to which the given path belongs.

        Args:
            path: Inbound path for which the wallet shall be returned.

        Raises:
            KeyNotFoundError: if given key does not belong to handled_keys

        """
        wallet_id = self._path_mappings.get(path)
        if wallet_id is None:
            raise WalletNotFoundError()

        return wallet_id

    async def add_connection(self, connection_id: str, wallet_id: str):
        """
        Add a mapping between the given connection and wallet.

        Args:
            connection_id: Indentifier of the new connection.
            wallet_id: Identifier of the wallet the connection belongs to.
        """
        self._connections[connection_id] = wallet_id

    async def add_key(self, key: str, wallet_id: str):
        """
        Add a mapping between the given connection and wallet.

        Args:
            connection_id: Indentifier of the new connection.
            wallet_id: Identifier of the wallet the connection belongs to.
        """
        self._handled_keys[key] = wallet_id

    async def get_wallet_for_connection(self, connection_id: str) -> str:
        """
        Return the identifier of the wallet to which the given key belongs.

        Args:
            connection_id: Verkey for which the wallet shall be returned.

        Raises:
            KeyNotFoundError: if given key does not belong to handled_keys

        Returns:
            Identifier of wallet associated to connection id.

        """
        if connection_id not in self._connections.keys():
            raise KeyNotFoundError()

        return self._connections[connection_id]

    async def get_wallet_for_key(self, key: str) -> str:
        """
        Return the identifier of the wallet to which the given key belongs.

        Args:
            key: Verkey for which the wallet shall be returned.

        Raises:
            KeyNotFoundError: if given key does not belong to handled_keys

        """
        if key not in self._handled_keys.keys():
            raise KeyNotFoundError()

        return self._handled_keys[key]