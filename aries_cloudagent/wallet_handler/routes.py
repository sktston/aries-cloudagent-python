"""Wallet handler admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
import hashlib
import re
from base64 import b64encode

from .handler import WalletHandler
from .error import WalletNotFoundError
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


class AddWalletSchema(Schema):
    """Request schema for adding a new wallet which will be registered by the agent."""

    wallet_name = fields.Str(
        description="Wallet identifier.",
        example='MyNewWallet'
    )
    wallet_key = fields.Str(
        description="Master key used for key derivation.",
        example='MySecretKey123'
    )
    seed = fields.Str(
        description="Seed used for did derivation.",
        example='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    )
    wallet_type = fields.Str(
        description="Type the newly generated wallet should be [basic | indy].",
        example='indy',
        default='indy'
    )


@docs(
    tags=["wallet"],
    summary="Add new wallet to be handled by this agent.",
)
@request_schema(AddWalletSchema())
async def wallet_handler_add_wallet(request: web.BaseRequest):
    """
    Request handler for adding a new wallet for handling by the agent.

    Args:
        request: aiohttp request object

    Raises:
        HTTPBadRequest: if no name is provided to identify new wallet.
        HTTPBadRequest: if a not supported wallet type is specified.

    """
    context = request.app["request_context"]

    body = await request.json()

    config = {}
    if body.get("wallet_name"):
        config["name"] = body.get("wallet_name")
    else:
        raise web.HTTPBadRequest(reason="Name needs to be provided to create a wallet.")
    config["key"] = body.get("wallet_key")
    wallet_type = body.get("wallet_type")
    if wallet_type not in WALLET_TYPES:
        raise web.HTTPBadRequest(reason="Specified wallet type is not supported.")
    config["type"] = wallet_type

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)

    try:
        await wallet_handler.add_instance(config, context)
    except WalletDuplicateError:
        raise web.HTTPBadRequest(reason="Wallet with specified name already exists.")

    return web.Response(body='created', status=201)


@docs(
    tags=["wallet"],
    summary="Get identifiers of all handled wallets.",
)
async def wallet_handler_get_wallets(request: web.BaseRequest):
    """
    Request handler to obtain all identifiers of the handled wallets.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]

    wallet_handler: WalletHandler = await context.inject(WalletHandler, required=False)
    wallet_names = await wallet_handler.get_instances()

    return web.json_response({"result": wallet_names})


@docs(
    tags=["wallet"],
    summary="Remove a wallet from handled wallets and delete it from storage.",
    parameters=[{"in": "path", "name": "id", "description": "Identifier of wallet."}],
)
async def wallet_handler_remove_wallet(request: web.BaseRequest):
    """
    Request handler to remove a wallet from agent and storage.

    Args:
        request: aiohttp request object.

    """
    context = request["context"]
    wallet_name = request.match_info["id"]

    wallet: BaseWallet = await context.inject(BaseWallet)

    if wallet.name != wallet_name:
        raise web.HTTPUnauthorized(reason="not owned wallet not allowed.")

    wallet_handler: WalletHandler = await context.inject(WalletHandler)

    try:
        await wallet_handler.delete_instance(wallet_name)
    #    raise web.HTTPBadRequest(reason="Wallet to delete not found.")
    except WalletNotFoundError:
        raise web.HTTPNotFound(reason=f"Requested wallet to delete not in storage.")
    except WalletError:
        raise web.HTTPError(reason=WalletError.message)

    return web.json_response({"result": "Deleted wallet {}".format(wallet_name)})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/wallet", wallet_handler_get_wallets, allow_head=False),
            web.post("/wallet", wallet_handler_add_wallet),
            web.post("/wallet/{id}/remove", wallet_handler_remove_wallet),
        ]
    )
