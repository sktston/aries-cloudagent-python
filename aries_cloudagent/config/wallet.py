"""Wallet configuration."""
import logging

from ..connections.models.connection_record import ConnectionRecord
from ..wallet.base import BaseWallet
from ..wallet.crypto import seed_to_did

from .base import ConfigError
from .injection_context import InjectionContext
from ..wallet.error import WalletDuplicateError
from ..wallet_handler import WalletHandler

LOGGER = logging.getLogger(__name__)


async def wallet_config(context: InjectionContext, provision: bool = False):
    """Initialize the wallet."""
    wallet: BaseWallet = await context.inject(BaseWallet)
    if provision:
        if wallet.type != "indy":
            raise ConfigError("Cannot provision a non-Indy wallet type")
        if wallet.created:
            print("Created new wallet")
        else:
            print("Opened existing wallet")
        print("Wallet type:", wallet.type)
        print("Wallet name:", wallet.name)

    wallet_seed = context.settings.get("wallet.seed")
    wallet_local_did = context.settings.get("wallet.local_did")
    public_did_info = await wallet.get_public_did()
    public_did = None

    if public_did_info:
        public_did = public_did_info.did
        if wallet_seed and seed_to_did(wallet_seed) != public_did:
            if context.settings.get("wallet.replace_public_did"):
                replace_did_info = await wallet.create_local_did(wallet_seed)
                public_did = replace_did_info.did
                await wallet.set_public_did(public_did)
                print(f"Created new public DID: {public_did}")
                print(f"Verkey: {replace_did_info.verkey}")
            else:
                # If we already have a registered public did and it doesn't match
                # the one derived from `wallet_seed` then we error out.
                raise ConfigError(
                    "New seed provided which doesn't match the registered"
                    + f" public did {public_did}"
                )
        # wait until ledger config to set public DID endpoint - wallet goes first
    elif wallet_seed:
        if wallet_local_did:
            endpoint = context.settings.get("default_endpoint")
            metadata = {"endpoint": endpoint} if endpoint else None

            local_did_info = await wallet.create_local_did(
                seed=wallet_seed, metadata=metadata
            )
            local_did = local_did_info.did
            if provision:
                print(f"Created new local DID: {local_did}")
                print(f"Verkey: {local_did_info.verkey}")
        else:
            public_did_info = await wallet.create_public_did(seed=wallet_seed)
            public_did = public_did_info.did
            if provision:
                print(f"Created new public DID: {public_did}")
                print(f"Verkey: {public_did_info.verkey}")
            # wait until ledger config to set public DID endpoint - wallet goes first

    if provision and not wallet_local_did and not public_did:
        print("No public DID")

    # Debug settings
    test_seed = context.settings.get("debug.seed")
    if context.settings.get("debug.enabled"):
        if not test_seed:
            test_seed = "testseed000000000000000000000001"
    if test_seed:
        await wallet.create_local_did(
            seed=test_seed, metadata={"endpoint": "1.2.3.4:8021"}
        )

    # add wallet config in admin storage if not exist
    ext_plugins = context.settings.get_value("external_plugins")
    if ext_plugins and 'aries_cloudagent.wallet_handler' in ext_plugins:
        config = {}
        config["name"] = wallet.name
        config["key"] = wallet._key
        config["type"] = wallet.type
        config["label"] = context.settings.get("default_label")
        config["image_url"] = ""
        config["webhook_urls"] = context.settings.get("admin.webhook_urls")

        wallet_handler: WalletHandler = await context.inject(WalletHandler)

        # store config to storage if not exist
        try:
            await wallet_handler.add_wallet(context, config)
        except WalletDuplicateError:
            await wallet_handler.update_wallet(
                context=context,
                new_config=config,
                wallet_name=wallet.name)

        # load information of admin wallet to wallet_handler
        # Get dids and check for paths in metadata.
        dids = await wallet.get_local_dids()
        for did in dids:
            await wallet_handler.add_key(did.verkey, wallet.name)

        # Add connections of opened wallet to handler.
        records = await ConnectionRecord.query(context)
        connections = [record.serialize() for record in records]
        for connection in connections:
            await wallet_handler.add_connection(connection["connection_id"], wallet.name)

        await wallet_handler.add_label(config["name"], config["label"])
        await wallet_handler.add_image_url(config["name"], config["image_url"])
        await wallet_handler.add_webhook_urls(config["name"], config["webhook_urls"])

    return public_did
