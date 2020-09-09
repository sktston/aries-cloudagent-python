"""Wallet handler admin routes."""
import json

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema
import hashlib
import re
from base64 import b64encode

from .handler import WalletHandler
from .error import WalletNotFoundError, WalletAccessError
from ..messaging.valid import UUIDFour
from ..wallet.base import BaseWallet
from ..wallet.error import WalletError, WalletDuplicateError

# from ..storage.base import BaseStorage
# from ..storage.record import StorageRecord
from ..storage.error import StorageNotFoundError

from ..protocols.connections.v1_0.manager import ConnectionManager
from ..protocols.connections.v1_0.routes import (
    InvitationResultSchema,
)

from ..connections.models.connection_record import (
    ConnectionRecord,
    ConnectionRecordSchema,
)

from ..protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
    ConnectionInvitationSchema,
)

from marshmallow import fields, Schema

WALLET_TYPES = {
    "basic": "aries_cloudagent.wallet.basic.BasicWallet",
    "indy": "aries_cloudagent.wallet.indy.IndyWallet",
}


async def create_connection_handle(wallet: BaseWallet, n: int) -> str:
    """
    Create a new path for the currently active wallet.

    Returns:
        path: path to use as postfix to add to default endpoint

    """
    id_raw = wallet.name + '_' + str(n)
    digest = hashlib.sha256(str.encode(id_raw)).digest()
    id = b64encode(digest).decode()
    # Clear all special characters
    path = re.sub('[^a-zA-Z0-9 \n]', '', id)

    return path


class WalletSchema(Schema):
    """schema for adding a new wallet which will be registered by the agent."""

    name = fields.Str(required=True, description="wallet name", example='faber',)
    key = fields.Str(required=True, description="master key used for key derivation", example='faber.key.123',)
    type = fields.Str(required=True, description="type of wallet [basic | indy]",example='indy',)


class WalletRecordSchema(WalletSchema):
    """Schema for a wallet record."""

    wallet_id = fields.Str(description="wallet identifier", example=UUIDFour.EXAMPLE,)
    storage_type = fields.Str(description="storage type", example=None,)
    storage_config = fields.Str(description="storage config", example=None,)
    storage_creds = fields.Str(description="storage creds", example=None,)


class WalletRecordListSchema(Schema):
    """Schema for a list of wallets."""

    results = fields.List(fields.Nested(WalletRecordSchema()), description="a list of wallet")


class WalletIdMatchInfoSchema(Schema):
    """Path parameters and validators for request taking wallet id."""

    wallet_id = fields.Str(description="wallet identifier", example=UUIDFour.EXAMPLE,)


@docs(tags=["wallet"], summary="Add a new wallet",)
@request_schema(WalletSchema())
@response_schema(WalletRecordSchema(), 201)
async def wallet_handler_add_wallet(request: web.BaseRequest):
    """
    Request handler for adding a new wallet for handling by the agent.

    Args:
        request: aiohttp request object

    Raises:
        HTTPBadRequest: if no name is provided to identify new wallet.
        HTTPBadRequest: if a not supported wallet type is specified.

    """
    context = request["context"]

    wallet: BaseWallet = await context.inject(BaseWallet)
    # admin only can do this
    if wallet.name != context.settings.get_value("wallet.name"):
        raise web.HTTPUnauthorized(reason="only admin wallet allowed.")

    body = await request.json()

    config = {}
    if body.get("name"):
        config["name"] = body.get("name")
    else:
        raise web.HTTPBadRequest(reason="Name needs to be provided to create a wallet.")
    config["key"] = body.get("key")
    wallet_type = body.get("type")
    if wallet_type not in WALLET_TYPES:
        raise web.HTTPBadRequest(reason="Specified wallet type is not supported.")
    config["type"] = wallet_type

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)

    try:
        record = await wallet_handler.add_instance(config, context)
    except WalletDuplicateError:
        raise web.HTTPBadRequest(reason="Wallet with specified name already exists.")

    record_dict = json.loads(record.value)
    record_dict["wallet_id"] = record.id
    return web.json_response(record_dict, status=201)


@docs(tags=["wallet"], summary="Get a list of wallets",)
@response_schema(WalletRecordListSchema(), 200)
async def wallet_handler_get_wallets(request: web.BaseRequest):
    """
    Request handler to obtain all identifiers of the handled wallets.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]
    wallet: BaseWallet = await context.inject(BaseWallet)
    # admin only can do this
    if wallet.name != context.settings.get_value("wallet.name"):
        raise web.HTTPUnauthorized(reason="only admin wallet allowed.")

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)
    record_list = await wallet_handler.get_instances(context)

    results = []
    for record in record_list:
        record_dict = json.loads(record.value)
        record_dict["wallet_id"] = record.id
        results.append(record_dict)
    return web.json_response({"results": results})


@docs(tags=["wallet"], summary="Remove a wallet",)
@match_info_schema(WalletIdMatchInfoSchema())
async def wallet_handler_remove_wallet(request: web.BaseRequest):
    """
    Request handler to remove a wallet from agent and storage.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]
    wallet_id = request.match_info["wallet_id"]

    wallet: BaseWallet = await context.inject(BaseWallet)
    # admin only can do this
    if wallet.name != context.settings.get_value("wallet.name"):
        raise web.HTTPUnauthorized(reason="only admin wallet allowed.")

    wallet_handler: WalletHandler = await context.inject(WalletHandler)

    try:
        await wallet_handler.delete_instance(wallet_id, context)
    #    raise web.HTTPBadRequest(reason="Wallet to delete not found.")
    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"Requested wallet to delete not in storage.")
    except WalletAccessError:
        raise web.HTTPBadRequest(reason="deleting admin wallet is not allowed")
    except WalletError:
        raise web.HTTPError(reason=WalletError.message)

    return web.Response(status=204)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/wallet", wallet_handler_get_wallets, allow_head=False),
            web.post("/wallet", wallet_handler_add_wallet),
            web.delete("/wallet/{wallet_id}", wallet_handler_remove_wallet),
        ]
    )
