"""Revocation registry admin routes."""

import logging

from asyncio import shield

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields, validate

from ..indy.util import tails_path
from ..messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from ..messaging.models.openapi import OpenAPISchema
from ..messaging.valid import INDY_CRED_DEF_ID, INDY_REV_REG_ID
from ..storage.base import BaseStorage, StorageNotFoundError
from ..tails.base import BaseTailsServer

from .error import RevocationError, RevocationNotSupportedError
from .indy import IndyRevocation
from .models.issuer_rev_reg_record import IssuerRevRegRecord, IssuerRevRegRecordSchema

LOGGER = logging.getLogger(__name__)


class RevRegCreateRequestSchema(OpenAPISchema):
    """Request schema for revocation registry creation request."""

    credential_definition_id = fields.Str(
        description="Credential definition identifier", **INDY_CRED_DEF_ID
    )
    max_cred_num = fields.Int(
        description="Maximum credential numbers", example=100, required=False
    )


class RevRegResultSchema(OpenAPISchema):
    """Result schema for revocation registry creation request."""

    result = IssuerRevRegRecordSchema()


class RevRegsCreatedSchema(OpenAPISchema):
    """Result schema for request for revocation registries created."""

    rev_reg_ids = fields.List(
        fields.Str(description="Revocation Registry identifiers", **INDY_REV_REG_ID)
    )


class RevRegUpdateTailsFileUriSchema(OpenAPISchema):
    """Request schema for updating tails file URI."""

    tails_public_uri = fields.Url(
        description="Public URI to the tails file",
        example=(
            "http://192.168.56.133:6543/revocation/registry/"
            f"{INDY_REV_REG_ID['example']}/tails-file"
        ),
        required=True,
    )


class RevRegsCreatedQueryStringSchema(OpenAPISchema):
    """Query string parameters and validators for rev regs created request."""

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )
    state = fields.Str(
        description="Revocation registry state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(IssuerRevRegRecord, m)
                for m in vars(IssuerRevRegRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class SetRevRegStateQueryStringSchema(OpenAPISchema):
    """Query string parameters and validators for request to set rev reg state."""

    state = fields.Str(
        description="Revocation registry state to set",
        required=True,
        validate=validate.OneOf(
            [
                getattr(IssuerRevRegRecord, m)
                for m in vars(IssuerRevRegRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class RevRegIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking rev reg id."""

    rev_reg_id = fields.Str(
        description="Revocation Registry identifier",
        required=True,
        **INDY_REV_REG_ID,
    )


class CredDefIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking cred def id."""

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=True,
        **INDY_CRED_DEF_ID,
    )


@docs(tags=["revocation"], summary="Creates a new revocation registry")
@request_schema(RevRegCreateRequestSchema())
@response_schema(RevRegResultSchema(), 200)
async def create_rev_reg(request: web.BaseRequest):
    """
    Request handler to create a new revocation registry.

    Args:
        request: aiohttp request object

    Returns:
        The issuer revocation registry record

    """
    context = request["context"]

    body = await request.json()

    credential_definition_id = body.get("credential_definition_id")
    max_cred_num = body.get("max_cred_num")

    # check we published this cred def
    storage = await context.inject(BaseStorage)

    found = await storage.search_records(
        type_filter=CRED_DEF_SENT_RECORD_TYPE,
        tag_query={"cred_def_id": credential_definition_id},
    ).fetch_all()
    if not found:
        raise web.HTTPNotFound(
            reason=f"Not issuer of credential definition id {credential_definition_id}"
        )

    try:
        revoc = IndyRevocation(context)
        issuer_rev_reg_rec = await revoc.init_issuer_registry(
            credential_definition_id,
            max_cred_num=max_cred_num,
        )
    except RevocationNotSupportedError as e:
        raise web.HTTPBadRequest(reason=e.message) from e
    await shield(issuer_rev_reg_rec.generate_registry(context))

    return web.json_response({"result": issuer_rev_reg_rec.serialize()})


@docs(
    tags=["revocation"],
    summary="Search for matching revocation registries that current agent created",
)
@querystring_schema(RevRegsCreatedQueryStringSchema())
@response_schema(RevRegsCreatedSchema(), 200)
async def rev_regs_created(request: web.BaseRequest):
    """
    Request handler to get revocation registries that current agent created.

    Args:
        request: aiohttp request object

    Returns:
        List of identifiers of matching revocation registries.

    """
    context = request["context"]

    search_tags = [
        tag for tag in vars(RevRegsCreatedQueryStringSchema)["_declared_fields"]
    ]
    tag_filter = {
        tag: request.query[tag] for tag in search_tags if tag in request.query
    }
    found = await IssuerRevRegRecord.query(context, tag_filter)

    return web.json_response({"rev_reg_ids": [record.revoc_reg_id for record in found]})


@docs(
    tags=["revocation"],
    summary="Get revocation registry by revocation registry id",
)
@match_info_schema(RevRegIdMatchInfoSchema())
@response_schema(RevRegResultSchema(), 200)
async def get_rev_reg(request: web.BaseRequest):
    """
    Request handler to get a revocation registry by rev reg id.

    Args:
        request: aiohttp request object

    Returns:
        The revocation registry

    """
    context = request["context"]

    rev_reg_id = request.match_info["rev_reg_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


@docs(
    tags=["revocation"],
    summary="Get current active revocation registry by credential definition id",
)
@match_info_schema(CredDefIdMatchInfoSchema())
@response_schema(RevRegResultSchema(), 200)
async def get_active_rev_reg(request: web.BaseRequest):
    """
    Request handler to get current active revocation registry by cred def id.

    Args:
        request: aiohttp request object

    Returns:
        The revocation registry identifier

    """
    context = request["context"]

    cred_def_id = request.match_info["cred_def_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_active_issuer_rev_reg_record(cred_def_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


@docs(
    tags=["revocation"],
    summary="Download tails file",
    produces="application/octet-stream",
    responses={200: {"description": "tails file"}},
)
@match_info_schema(RevRegIdMatchInfoSchema())
async def get_tails_file(request: web.BaseRequest) -> web.FileResponse:
    """
    Request handler to download tails file for revocation registry.

    Args:
        request: aiohttp request object

    Returns:
        The tails file in FileResponse

    """
    context = request["context"]

    rev_reg_id = request.match_info["rev_reg_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.FileResponse(path=rev_reg.tails_local_path, status=200)


@docs(
    tags=["revocation"],
    summary="Upload local tails file to server",
)
@match_info_schema(RevRegIdMatchInfoSchema())
async def upload_tails_file(request: web.BaseRequest):
    """
    Request handler to upload local tails file for revocation registry.

    Args:
        request: aiohttp request object

    """
    context = request.app["request_context"]

    rev_reg_id = request.match_info["rev_reg_id"]

    tails_server: BaseTailsServer = await context.inject(
        BaseTailsServer,
        required=False,
    )
    if not tails_server:
        raise web.HTTPForbidden(reason="No tails server configured")

    loc_tails_path = tails_path(rev_reg_id)
    if not loc_tails_path:
        raise web.HTTPNotFound(reason=f"No local tails file for rev reg {rev_reg_id}")
    (upload_success, reason) = await tails_server.upload_tails_file(
        context,
        rev_reg_id,
        loc_tails_path,
        interval=0.8,
        backoff=-0.5,
        max_attempts=16,
    )
    if not upload_success:
        raise web.HTTPInternalServerError(reason=reason)

    return web.json_response()


@docs(
    tags=["revocation"],
    summary="Send revocation registry definition to ledger",
)
@match_info_schema(RevRegIdMatchInfoSchema())
@response_schema(RevRegResultSchema(), 200)
async def send_rev_reg_def(request: web.BaseRequest):
    """
    Request handler to send revocation registry definition by reg reg id to ledger.

    Args:
        request: aiohttp request object

    Returns:
        The issuer revocation registry record

    """
    context = request["context"]
    registry_id = request.match_info["rev_reg_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)

        await rev_reg.send_def(context)
        LOGGER.debug("published rev reg definition: %s", rev_reg_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except RevocationError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


@docs(
    tags=["revocation"],
    summary="Send revocation registry entry to ledger",
)
@match_info_schema(RevRegIdMatchInfoSchema())
@response_schema(RevRegResultSchema(), 200)
async def send_rev_reg_entry(request: web.BaseRequest):
    """
    Request handler to send rev reg entry by registry id to ledger.

    Args:
        request: aiohttp request object

    Returns:
        The revocation registry record

    """
    context = request.app["request_context"]
    rev_reg_id = request.match_info["rev_reg_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
        await rev_reg.send_entry(context)
        LOGGER.debug("published registry entry: %s", rev_reg_id)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    except RevocationError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


@docs(
    tags=["revocation"],
    summary="Update revocation registry with new public URI to its tails file",
)
@match_info_schema(RevRegIdMatchInfoSchema())
@request_schema(RevRegUpdateTailsFileUriSchema())
@response_schema(RevRegResultSchema(), 200)
async def update_rev_reg(request: web.BaseRequest):
    """
    Request handler to update a rev reg's public tails URI by registry id.

    Args:
        request: aiohttp request object

    Returns:
        The revocation registry record

    """
    context = request["context"]

    body = await request.json()
    tails_public_uri = body.get("tails_public_uri")

    rev_reg_id = request.match_info["rev_reg_id"]

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
        await rev_reg.set_tails_file_public_uri(context, tails_public_uri)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except RevocationError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


@docs(tags=["revocation"], summary="Set revocation registry state manually")
@match_info_schema(RevRegIdMatchInfoSchema())
@querystring_schema(SetRevRegStateQueryStringSchema())
@response_schema(RevRegResultSchema(), 200)
async def set_rev_reg_state(request: web.BaseRequest):
    """
    Request handler to set a revocation registry state manually.

    Args:
        request: aiohttp request object

    Returns:
        The revocation registry record, updated

    """
    context = request.app["request_context"]
    rev_reg_id = request.match_info["rev_reg_id"]
    state = request.query.get("state")

    try:
        revoc = IndyRevocation(context)
        rev_reg = await revoc.get_issuer_rev_reg_record(rev_reg_id)
        await rev_reg.set_state(context, state)

        LOGGER.debug("set registry %s state: %s", rev_reg_id, state)

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response({"result": rev_reg.serialize()})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/revocation/create-registry", create_rev_reg),
            web.get(
                "/revocation/registries/created",
                rev_regs_created,
                allow_head=False,
            ),
            web.get("/revocation/registry/{rev_reg_id}", get_rev_reg, allow_head=False),
            web.get(
                "/revocation/active-registry/{cred_def_id}",
                get_active_rev_reg,
                allow_head=False,
            ),
            web.get(
                "/revocation/registry/{rev_reg_id}/tails-file",
                get_tails_file,
                allow_head=False,
            ),
            web.put("/revocation/registry/{rev_reg_id}/tails-file", upload_tails_file),
            web.patch("/revocation/registry/{rev_reg_id}", update_rev_reg),
            web.post("/revocation/registry/{rev_reg_id}/definition", send_rev_reg_def),
            web.post("/revocation/registry/{rev_reg_id}/entry", send_rev_reg_entry),
            web.patch(
                "/revocation/registry/{rev_reg_id}/set-state",
                set_rev_reg_state,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "revocation",
            "description": "Revocation registry management",
            "externalDocs": {
                "description": "Overview",
                "url": (
                    "https://github.com/hyperledger/indy-hipe/tree/"
                    "master/text/0011-cred-revocation"
                ),
            },
        }
    )

    # aio_http-apispec polite API only works on schema for JSON objects, not files yet
    methods = app._state["swagger_dict"]["paths"].get(
        "/revocation/registry/{rev_reg_id}/tails-file"
    )
    if methods:
        methods["get"]["responses"]["200"]["schema"] = {
            "type": "string",
            "format": "binary",
        }
