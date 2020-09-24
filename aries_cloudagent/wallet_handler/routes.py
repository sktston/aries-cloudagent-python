"""Wallet handler admin routes."""
import json

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema, match_info_schema, querystring_schema
import hashlib
import re
from base64 import b64encode

from .handler import WalletHandler
from .error import WalletNotFoundError, WalletAccessError
from ..messaging.models.openapi import OpenAPISchema
from ..messaging.valid import UUIDFour
from ..storage.record import StorageRecord
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


class WalletUpdateSchema(Schema):
    """schema for updating a wallet."""

    label = fields.Str(required=True, description="my name when connection is established", example='faber',)


class WalletSchema(Schema):
    """schema for adding a new wallet which will be registered by the agent."""

    name = fields.Str(required=True, description="wallet name", example='faber',)
    key = fields.Str(required=True, description="master key used for key derivation", example='faber.key.123',)
    type = fields.Str(required=True, description="type of wallet [indy]", example='indy',)
    label = fields.Str(required=False, description="my name when connection is established", example='faber',)


class WalletRecordSchema(WalletSchema):
    """Schema for a wallet record."""

    wallet_id = fields.Str(description="wallet identifier", example=UUIDFour.EXAMPLE,)


class WalletRecordListSchema(Schema):
    """Schema for a list of wallets."""

    results = fields.List(fields.Nested(WalletRecordSchema()), description="a list of wallet")


class WalletIdMatchInfoSchema(Schema):
    """Path parameters and validators for request taking wallet id."""

    wallet_id = fields.Str(description="wallet identifier", example=UUIDFour.EXAMPLE,)


class WalletRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for wallet list request query string."""

    name = fields.Str(description="wallet name of interest", required=False, example="faber")


def get_wallet_record(record: StorageRecord):
    """
    Get wallet record from StorageRecord.

    Args:
        record: StorageRecord.
    """
    wallet_record = json.loads(record.value)
    del wallet_record["storage_type"]
    del wallet_record["storage_config"]
    del wallet_record["storage_creds"]
    wallet_record["wallet_id"] = record.id

    return wallet_record


@docs(tags=["wallet"], summary="Get a list of wallets (admin only)",)
@querystring_schema(WalletRecordListQueryStringSchema())
@response_schema(WalletRecordListSchema(), 200)
async def wallet_handler_get_wallets(request: web.BaseRequest):
    """
    Request handler to get a list of wallets.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]
    wallet: BaseWallet = await context.inject(BaseWallet)
    # admin only can do this
    if wallet.name != context.settings.get_value("wallet.name"):
        raise web.HTTPUnauthorized(reason="only admin wallet allowed.")

    query = {}
    if request.query.get("name"):
        query["name"] = request.query.get("name")

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)
    record_list = await wallet_handler.get_wallet_list(context, query)

    results = []
    for record in record_list:
        wallet_record = get_wallet_record(record)
        results.append(wallet_record)
    return web.json_response({"results": results})


@docs(tags=["wallet"], summary="Get my wallet",)
@response_schema(WalletRecordSchema(), 200)
async def wallet_handler_get_my_wallet(request: web.BaseRequest):
    """
    Request handler to get my wallet.

    Args:
        request: aiohttp request object

    """
    context = request["context"]

    wallet: BaseWallet = await context.inject(BaseWallet)
    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)
    record_list = await wallet_handler.get_wallet_list(context, {"name": wallet.name})

    if record_list:
        record = record_list[0]
    else:
        raise web.HTTPNotFound(reason="Not found the specified name of wallet.")

    return web.json_response(get_wallet_record(record))


@docs(tags=["wallet"], summary="Add a new wallet (admin only)",)
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

    config = {"name": body.get("name"), "key": body.get("key"), "type": body.get("type"), "label": body.get("label")}
    if not config["label"]:
        config["label"] = config["name"]

    if config["type"] not in WALLET_TYPES:
        raise web.HTTPBadRequest(reason="Specified wallet type is not supported.")

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)
    try:
        record = await wallet_handler.add_wallet(context, config)
    except WalletDuplicateError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(get_wallet_record(record), status=201)


@docs(tags=["wallet"], summary="Remove a wallet (admin only)",)
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
        await wallet_handler.remove_wallet(context=context, wallet_id=wallet_id)
    except WalletNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except WalletAccessError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(tags=["wallet"], summary="Remove my wallet",)
async def wallet_handler_remove_my_wallet(request: web.BaseRequest):
    """
    Request handler to remove my wallet from agent and storage.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]

    wallet: BaseWallet = await context.inject(BaseWallet)
    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)

    try:
        await wallet_handler.remove_wallet(context=context, wallet_name=wallet.name)
    except WalletNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except WalletAccessError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except WalletError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(tags=["wallet"], summary="Update my wallet",)
@request_schema(WalletUpdateSchema())
@response_schema(WalletRecordSchema(), 200)
async def wallet_handler_update_my_wallet(request: web.BaseRequest):
    """
    Request handler to update my wallet from agent and storage.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]
    body = await request.json()
    my_label = body.get("label")

    wallet: BaseWallet = await context.inject(BaseWallet)
    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)

    try:
        record = await wallet_handler.update_wallet(context=context, my_label=my_label, wallet_name=wallet.name)
    except WalletNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(get_wallet_record(record))


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/wallet", wallet_handler_get_wallets, allow_head=False),
            web.get("/wallet/me", wallet_handler_get_my_wallet, allow_head=False),
            web.post("/wallet", wallet_handler_add_wallet),
            web.put("/wallet/me", wallet_handler_update_my_wallet),
            web.delete("/wallet/me", wallet_handler_remove_my_wallet),
            web.delete("/wallet/{wallet_id}", wallet_handler_remove_wallet),
        ]
    )
