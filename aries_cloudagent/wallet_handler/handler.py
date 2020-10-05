"""Multi wallet handler implementation of BaseWallet interface."""

import json
import uuid

import indy.anoncreds
import indy.did
import indy.crypto
import logging
from indy.error import IndyError, ErrorCode
from base64 import b64decode

from ..storage.error import StorageNotFoundError
from ..storage.record import StorageRecord
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
from ..cache.base import BaseCache

from .error import KeyNotFoundError, WalletAccessError
from .error import WalletNotFoundError

LOGGER = logging.getLogger(__name__)

WALLET_CONFIG_RECORD_TYPE = "wallet_config"


class WalletHandler():
    """Class to handle multiple wallets."""

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

        # Maps: `verkey` -> `wallet`
        self._handled_keys = {}
        # Maps: `connection_id` -> `wallet`
        self._connections = {}
        # Maps: `wallet` -> `label`
        self._labels = {}
        # Maps: `wallet` -> `image_url`
        self._image_urls = {}
        # Maps: `wallet` -> `webhook_urls`
        self._webhook_urls_dict = {}

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
        if config["name"] in self._provider._instances.keys():
            raise WalletDuplicateError()

        wallet = ClassLoader.load_class(self.DEFAULT_WALLET_CLASS)(config)
        await wallet.open()

        # create storage for new wallet
        storage = ClassLoader.load_class(self.DEFAULT_STORAGE_CLASS)(wallet)

        # create ledger for new wallet
        pool_name = wallet.name
        keepalive = int(context.settings.get("ledger.keepalive", 5))
        IndyLedger = ClassLoader.load_class(self.DEFAULT_LEDGER_CLASS)
        cache = await context.inject(BaseCache, required=False)
        ledger = IndyLedger(
            pool_name, wallet, keepalive=keepalive, cache=cache
        )
        genesis_transactions = context.settings.get("ledger.genesis_transactions")
        if genesis_transactions:
            await ledger.create_pool_config(genesis_transactions, True)
        elif not await ledger.check_pool_config():
            LOGGER.info("Ledger pool configuration has not been created")
            ledger = None

        # Store wallet in wallet provider.
        # Store storage and ledger in dynamic provider
        self._provider._instances[wallet.name] = wallet
        storage_provider = context.injector._providers[BaseStorage]
        storage_provider._instances[wallet.name] = storage
        ledger_provider = context.injector._providers[BaseLedger]
        ledger_provider._instances[wallet.name] = ledger

        # Get dids and check for paths in metadata.
        dids = await wallet.get_local_dids()
        for did in dids:
            await self.add_key(did.verkey, wallet.name)

        # Without changing the requested instance, the storage provider
        # picks up the correct wallet for fetching the connections.
        user_context = context.copy()
        user_context.settings.set_value("wallet.id", wallet.name)

        # Add connections of opened wallet to handler.
        records = await ConnectionRecord.query(user_context)
        connections = [record.serialize() for record in records]
        for connection in connections:
            await self.add_connection(connection["connection_id"], config["name"])

        await self.update_instance(config)

    async def update_instance(self, config: dict):
        """
        Add a new instance to the handler to be used during runtime.

        Args:
            config: Settings for the updating instance.
        """
        await self.add_label(config["name"], config.get("label"))
        await self.add_image_url(config["name"], config.get("image_url"))
        await self.add_webhook_urls(config["name"], config.get("webhook_urls", []))

    async def set_instance(self, wallet_name: str, context: InjectionContext):
        """Set a specific wallet to open by the provider."""
        instances = await self.get_instances()
        if wallet_name not in instances:
            # wallet is not opened
            # search wallet in admin storage and open wallet if exist
            record_list = await self.get_wallet_list(context, {"name": wallet_name})
            if record_list:
                record = record_list[0]
                await self.add_instance(json.loads(record.value), context)
            else:
                raise WalletNotFoundError('Requested not existing wallet instance.')
        context.settings.set_value("wallet.id", wallet_name)

    async def delete_instance(self, context: InjectionContext, wallet_name: str):
        """
        Delete handled instance from handler and storage.

        Args:
            context: Injection context.
            wallet_name: Identifier of the instance to be deleted.
        """

        try:
            # Remove wallet in wallet provider.
            wallet = self._provider._instances.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"Wallet not found: {wallet_name}")

        try:
            # Remove storage in dynamic provider
            storage_provider = context.injector._providers[BaseStorage]
            storage_provider._instances.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"storage_provider of wallet name {wallet_name} is not found")

        try:
            # Remove ledger in dynamic provider
            ledger_provider = context.injector._providers[BaseLedger]
            ledger_provider._instances.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"ledger_provider of wallet name {wallet_name} is not found")

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

        # Remove all mappings of wallet.
        self._handled_keys = {
            key: val for key, val in self._handled_keys.items() if val != wallet_name
            }
        self._connections = {
            key: val for key, val in self._connections.items() if val != wallet_name
            }

        try:
            # Remove label in wallet provider.
            self._labels.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"label of wallet name {wallet_name} is not found")

        try:
            # Remove label in wallet provider.
            self._image_urls.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"image_url of wallet name {wallet_name} is not found")

        try:
            # Remove webhook_url_list in wallet provider.
            self._webhook_urls_dict.pop(wallet_name)
        except KeyError:
            raise WalletNotFoundError(f"webhook_urls of wallet name {wallet_name} is not found")

    async def get_wallet_list(self, context: InjectionContext, query: dict = None, ):
        """
        Return list of wallets

        Args:
            context: Injection context.
            query: query
        """
        # search wallets in admin storage (caller can be normal wallet, we change to admin context)
        admin_context = context.copy()
        admin_context.settings.set_value("wallet.id", context.settings.get_value("wallet.name"))
        storage: BaseStorage = await admin_context.inject(BaseStorage)
        record_list = await storage.search_records(
            type_filter=WALLET_CONFIG_RECORD_TYPE,
            tag_query=query,
        ).fetch_all()

        return record_list

    async def get_wallet(self, context: InjectionContext, wallet_id: str):
        """
        Return a wallet

        Args:
            context: Injection context.
            wallet_id: identifier of wallet
        """
        # search wallets in admin storage (caller can be normal wallet, we change to admin context)
        admin_context = context.copy()
        admin_context.settings.set_value("wallet.id", context.settings.get_value("wallet.name"))
        storage: BaseStorage = await admin_context.inject(BaseStorage)

        try:
            record = await storage.get_record(
                record_type=WALLET_CONFIG_RECORD_TYPE,
                record_id=wallet_id,
            )
        except StorageNotFoundError:
            return None

        return record

    async def add_wallet(self, context: InjectionContext, config: dict):
        """
        Add a new wallet

        Args:
            context: Injection context.
            config: Settings for the new instance.
        """
        # Pass default values into config
        config["storage_type"] = self._storage_type
        config["storage_config"] = self._storage_config
        config["storage_creds"] = self._storage_creds

        # check wallet name is already exist
        wallet_name = config["name"]
        record_list = await self.get_wallet_list(context, {"name": wallet_name})
        if record_list:
            raise WalletDuplicateError(f"specified wallet name exist: {wallet_name}")

        # add record of wallet (admin context is assumed)
        storage: BaseStorage = await context.inject(BaseStorage)
        record = StorageRecord(
            type=WALLET_CONFIG_RECORD_TYPE,
            value=json.dumps(config),
            tags={"name": wallet_name},
            id=str(uuid.uuid4()),
        )
        await storage.add_record(record)

        # open wallet if not opened
        instances = await self.get_instances()
        if wallet_name not in instances:
            await self.add_instance(config, context)

        return record

    async def remove_wallet(
            self,
            context: InjectionContext,
            wallet_id: str = None,
            wallet_name: str = None,
    ):
        """
        Remove a wallet

        Args:
            context: Injection context.
            wallet_id: Identifier of the instance to be deleted.
            wallet_name: name of the instance to be deleted.
        """
        # get record
        if wallet_id:
            record = await self.get_wallet(context, wallet_id)
            if not record:
                raise WalletNotFoundError(f"specified wallet id is not found: {wallet_id}")
        elif wallet_name:
            record_list = await self.get_wallet_list(context, {"name": wallet_name})
            if record_list:
                record = record_list[0]
            else:
                raise WalletNotFoundError(f"specified wallet name is not found: {wallet_name}")
        else:
            raise WalletNotFoundError(f"wallet id or wallet id must be specified.")

        config = json.loads(record.value)
        wallet_name = config["name"]

        # can not delete admin wallet
        if wallet_name == context.settings.get_value("wallet.name"):
            raise WalletAccessError(f"deleting admin wallet is not allowed")

        # delete record in admin storage (caller can be normal wallet, we change to admin context)
        admin_context = context.copy()
        admin_context.settings.set_value("wallet.id", context.settings.get_value("wallet.name"))
        storage: BaseStorage = await admin_context.inject(BaseStorage)
        await storage.delete_record(record)

        # close wallet if opened
        # TODO: close wallets among all aca-py servers
        instances = await self.get_instances()
        if wallet_name in instances:
            await self.delete_instance(context, wallet_name)

    async def update_wallet(
            self,
            context: InjectionContext,
            new_config: dict,
            wallet_id: str = None,
            wallet_name: str = None,
    ):
        """
        Remove a wallet

        Args:
            context: Injection context.
            new_config: New settings for the instance.
            wallet_id: Identifier of the instance to be updated.
            wallet_name: name of the instance to be updated.
        """
        # get record
        if wallet_id:
            record = await self.get_wallet(context, wallet_id)
            if not record:
                raise WalletNotFoundError(f"specified wallet id is not found: {wallet_id}")
        elif wallet_name:
            record_list = await self.get_wallet_list(context, {"name": wallet_name})
            if record_list:
                record = record_list[0]
            else:
                raise WalletNotFoundError(f"specified wallet name is not found: {wallet_name}")
        else:
            raise WalletNotFoundError(f"wallet id or wallet id must be specified.")

        config = json.loads(record.value)
        if new_config["label"] is not None:
            config["label"] = new_config["label"]
        if new_config["image_url"] is not None:
            config["image_url"] = new_config["image_url"]
        if new_config["webhook_urls"] is not None:
            config["webhook_urls"] = new_config["webhook_urls"]

        # update record in admin storage (caller can be normal wallet, we change to admin context)
        admin_context = context.copy()
        admin_context.settings.set_value("wallet.id", context.settings.get_value("wallet.name"))
        storage: BaseStorage = await admin_context.inject(BaseStorage)
        await storage.update_record_value(record, json.dumps(config))
        record = await self.get_wallet(context, record.id)

        # update instance
        await self.update_instance(config)

        return record

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
            key: verification key of the new connection.
            wallet_id: Identifier of the wallet the connection belongs to.
        """
        self._handled_keys[key] = wallet_id

    async def add_label(self, wallet: str, label: str):
        """
        Add a mapping between the given connection and wallet.

        Args:
            wallet: wallet name.
            label: label of the wallet.
        """
        self._labels[wallet] = label

    async def add_image_url(self, wallet: str, image_url: str):
        """
        Add a mapping between the given connection and wallet.

        Args:
            wallet: wallet name.
            image_url: image_url of the wallet.
        """
        self._image_urls[wallet] = image_url

    async def add_webhook_urls(self, wallet: str, webhook_urls: str):
        """
        Add a mapping between the given connection and wallet.

        Args:
            wallet: wallet name.
            webhook_urls: webhook_urls of the wallet.
        """
        self._webhook_urls_dict[wallet] = webhook_urls

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

    async def get_label_for_wallet(self, wallet: str) -> str:
        """
        Return the label of the wallet to which the given wallet name.

        Args:
            wallet: wallet name for which the label shall be returned.

        Raises:
            KeyNotFoundError: if given wallet does not exist in _labels

        """
        if wallet not in self._labels.keys():
            raise KeyNotFoundError()

        return self._labels[wallet]

    async def get_image_url_for_wallet(self, wallet: str) -> str:
        """
        Return the image_url of the wallet to which the given wallet name.

        Args:
            wallet: wallet name for which the image_url shall be returned.

        Raises:
            KeyNotFoundError: if given wallet does not exist in _image_urls

        """
        if wallet not in self._image_urls.keys():
            raise KeyNotFoundError()

        return self._image_urls[wallet]

    async def get_webhook_urls_for_wallet(self, wallet: str) -> list:
        """
        Return the list of webhook url of the wallet to which the given wallet name.

        Args:
            wallet: wallet name for which the list of webhook url shall be returned.

        Raises:
            KeyNotFoundError: if given wallet does not exist in _image_urls

        """
        if wallet not in self._webhook_urls_dict.keys():
            raise KeyNotFoundError()

        return self._webhook_urls_dict[wallet]