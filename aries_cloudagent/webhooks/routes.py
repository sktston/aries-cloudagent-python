"""Webhook admin routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema

from marshmallow import fields, Schema

from ..storage.base import BaseStorage
from ..storage.error import StorageNotFoundError
from ..storage.record import StorageRecord

from .util import WEBHOOK_SENT_RECORD_TYPE


class GetWebhooksResultsSchema(Schema):
    """Results schema for getting a list of webhooks."""

    webhook_urls = fields.List(
        fields.Str(description="Webhook url", example="http://localhost:8022",)
    )


class WebhookSchema(Schema):
    """Request schema for adding/removing a webhook."""

    webhook_url = fields.Str(required=True, description="Webhook url", example="http://localhost:8022",)


class WebhookResultsSchema(Schema):
    """Results schema for adding/removing a webhook."""

    webhook_url = fields.Str(required=True, description="Webhook url", example="http://localhost:8022",)
    result = fields.Str(required=True, description="result of request", example="added | removed",)


@docs(tags=["webhook"], summary="Get all webhooks.")
@response_schema(GetWebhooksResultsSchema(), 200)
async def webhooks_get_webhooks(request: web.BaseRequest):
    """
    Request handler to get all webhooks.

    Args:
        request: aiohttp request object.

    Returns:
        a list of webhooks

    """
    context = request["context"]

    storage = await context.inject(BaseStorage)
    found = await storage.search_records(
        type_filter=WEBHOOK_SENT_RECORD_TYPE,
    ).fetch_all()

    return web.json_response({"webhook_urls": [record.value for record in found]})


@docs(tags=["webhook"], summary="Add a new webhook.")
@request_schema(WebhookSchema())
@response_schema(WebhookResultsSchema(), 200)
async def webhooks_add_webhook(request: web.BaseRequest):
    """
    Request handler for adding a new webhook.

    Args:
        request: aiohttp request object

    Returns:
        Result of the request

    """
    context = request["context"]
    body = await request.json()
    webhook_url = body.get("webhook_url")

    storage: BaseStorage = await context.inject(BaseStorage)
    try:
        result = await storage.search_records(
            type_filter=WEBHOOK_SENT_RECORD_TYPE,
            tag_query={"webhook_url": webhook_url},
        ).fetch_single()
        if result:
            raise web.HTTPBadRequest(reason="specified webhook_url already exists.")
    except StorageNotFoundError:
        pass

    record = StorageRecord(
        WEBHOOK_SENT_RECORD_TYPE,
        webhook_url,
        {"webhook_url": webhook_url}
    )
    await storage.add_record(record)

    return web.json_response({"webhook_url": webhook_url, "result": "added"})


@docs(tags=["webhook"], summary="Remove a webhook.")
@request_schema(WebhookSchema())
@response_schema(WebhookResultsSchema(), 200)
async def webhooks_remove_webhook(request: web.BaseRequest):
    """
    Request handler for removing a webhook.

    Args:
        request: aiohttp request object

    Returns:
        Result of the request

    """
    context = request["context"]
    body = await request.json()
    webhook_url = body.get("webhook_url")

    storage: BaseStorage = await context.inject(BaseStorage)

    try:
        result = await storage.search_records(
            type_filter=WEBHOOK_SENT_RECORD_TYPE,
            tag_query={"webhook_url": webhook_url},
        ).fetch_single()
        if result:
            await storage.delete_record(result)
    except StorageNotFoundError:
        raise web.HTTPBadRequest(reason="specified webhook_url does not exists.")

    return web.json_response({"webhook_url": webhook_url, "result": "removed"})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/webhooks", webhooks_get_webhooks, allow_head=False),
            web.post("/webhooks", webhooks_add_webhook),
            web.delete("/webhooks", webhooks_remove_webhook),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "webhook",
            "description": "webhook management",
        }
    )
