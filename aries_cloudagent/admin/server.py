"""Admin server classes."""

import asyncio
import json
import logging
from typing import Callable, Coroutine, Sequence, Set
import uuid

from aiohttp import web
from aiohttp_apispec import (
    docs,
    response_schema,
    setup_aiohttp_apispec,
    validation_middleware, request_schema, match_info_schema,
)
import aiohttp_cors

from marshmallow import fields, Schema

from ..config.injection_context import InjectionContext
from ..core.plugin_registry import PluginRegistry
from ..ledger.error import LedgerConfigError, LedgerTransactionError
from ..messaging.responder import BaseResponder
from ..messaging.valid import UUIDFour
from ..storage.base import BaseStorage
from ..storage.error import StorageNotFoundError
from ..storage.record import StorageRecord
from ..transport.queue.basic import BasicMessageQueue
from ..transport.outbound.message import OutboundMessage
from ..utils.stats import Collector
from ..utils.task_queue import TaskQueue
from ..version import __version__
from ..wallet_handler import WalletHandler
from ..wallet_handler.error import WalletNotFoundError

from .base_server import BaseAdminServer
from .error import AdminSetupError


LOGGER = logging.getLogger(__name__)

WEBHOOK_SENT_RECORD_TYPE = "webhook_sent"


class AdminModulesSchema(Schema):
    """Schema for the modules endpoint."""

    result = fields.List(
        fields.Str(description="admin module"), description="List of admin modules"
    )


class AdminStatusSchema(Schema):
    """Schema for the status endpoint."""


class AdminStatusLivelinessSchema(Schema):
    """Schema for the liveliness endpoint."""

    alive = fields.Boolean(description="Liveliness status", example=True)


class AdminStatusReadinessSchema(Schema):
    """Schema for the readiness endpoint."""

    ready = fields.Boolean(description="Readiness status", example=True)


class WebhookIdMatchInfoSchema(Schema):
    """Path parameters and validators for request taking webhook id."""

    webhook_id = fields.Str(description="webhook identifier", example=UUIDFour.EXAMPLE,)


class WebhookTargetSchema(Schema):
    """Schema for the webhook target."""

    target_url = fields.Str(required=True, description="webhook target url", example="http://localhost:8022/webhooks",)


class WebhookTargetRecordSchema(WebhookTargetSchema):
    """Schema for the webhook target record."""

    webhook_id = fields.Str(description="webhook identifier", example=UUIDFour.EXAMPLE,)
    topic_filter = fields.List(
        fields.Str(
            description="connections|issue_credential|present_proof|basicmessages|revocation_registry",
            example="connections",),
        required=False,
        description="topics controller want to receive (null means all)",
    )
    max_attempts = fields.Integer(required=False, description="max attempts (null means default value 4)", example=4,)


class WebhookTargetRecordListSchema(Schema):
    """Results schema for getting a list of webhook targets."""

    results = fields.List(fields.Nested(WebhookTargetRecordSchema()), description="a list of webhook targets")


class AdminResponder(BaseResponder):
    """Handle outgoing messages from message handlers."""

    def __init__(
        self, context: InjectionContext, send: Coroutine, webhook: Coroutine, **kwargs,
    ):
        """
        Initialize an instance of `AdminResponder`.

        Args:
            send: Function to send outbound message

        """
        super().__init__(**kwargs)
        self._context = context
        self._send = send
        self._webhook = webhook

    async def send_outbound(self, message: OutboundMessage):
        """
        Send outbound message.

        Args:
            message: The `OutboundMessage` to be sent
        """
        await self._send(self._context, message)

    async def send_webhook(self, context: InjectionContext, topic: str, payload: dict):
        """
        Dispatch a webhook.

        Args:
            context: The injection context to use
            topic: the webhook topic identifier
            payload: the webhook payload value
        """
        await self._webhook(context, topic, payload)


class WebhookTarget:
    """Class for managing webhook target information."""

    def __init__(
        self,
        target_url: str,
        topic_filter: Sequence[str] = None,
        max_attempts: int = None,
    ):
        """Initialize the webhook target."""
        self.target_url = target_url
        self.max_attempts = max_attempts
        self._topic_filter = None
        self.topic_filter = topic_filter  # call setter

    @property
    def topic_filter(self) -> Set[str]:
        """Accessor for the target's topic filter."""
        return self._topic_filter

    @topic_filter.setter
    def topic_filter(self, val: Sequence[str]):
        """Setter for the target's topic filter."""
        filter = set(val) if val else None
        if filter and "*" in filter:
            filter = None
        self._topic_filter = filter

    def serialize(self) -> str:
        """Dump current object to a JSON-compatible dictionary."""
        return {
            "target_url": self.target_url,
            "topic_filter": self.topic_filter,
            "max_attempts": self.max_attempts,
        }

    def to_json(self) -> str:
        """Return a JSON representation of the webhook target."""
        return json.dumps(self.serialize())

    @classmethod
    def deserialize(cls, webhook_target: dict) -> "WebhookTarget":
        """Construct webhook target object from dict representation."""
        return WebhookTarget(
            webhook_target["target_url"],
            webhook_target["topic_filter"],
            webhook_target["max_attempts"]
        )

    @classmethod
    def from_json(cls, webhook_target_json: str) -> "WebhookTarget":
        """Return a webhook target object from json representation."""
        return cls.deserialize(json.loads(webhook_target_json))


@web.middleware
async def ready_middleware(request: web.BaseRequest, handler: Coroutine):
    """Only continue if application is ready to take work."""

    if str(request.rel_url).rstrip("/") in (
        "/status/live",
        "/status/ready",
    ) or request.app._state.get("ready"):
        try:
            return await handler(request)
        except (LedgerConfigError, LedgerTransactionError) as e:
            # fatal, signal server shutdown
            LOGGER.error("Shutdown with %s", str(e))
            request.app._state["ready"] = False
            request.app._state["alive"] = False
            raise
        except Exception as e:
            # some other error?
            LOGGER.error("Handler error with exception: %s", str(e))
            raise e

    raise web.HTTPServiceUnavailable(reason="Shutdown in progress")


@web.middleware
async def debug_middleware(request: web.BaseRequest, handler: Coroutine):
    """Show request detail in debug log."""

    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(f"Incoming request: {request.method} {request.path_qs}")
        LOGGER.debug(f"Match info: {request.match_info}")
        body = await request.text()
        LOGGER.debug(f"Body: {body}")

    return await handler(request)


class AdminServer(BaseAdminServer):
    """Admin HTTP server class."""

    def __init__(
        self,
        host: str,
        port: int,
        context: InjectionContext,
        outbound_message_router: Coroutine,
        webhook_router: Callable,
        conductor_stop: Coroutine,
        task_queue: TaskQueue = None,
        conductor_stats: Coroutine = None,
    ):
        """
        Initialize an AdminServer instance.

        Args:
            host: Host to listen on
            port: Port to listen on
            context: The application context instance
            outbound_message_router: Coroutine for delivering outbound messages
            webhook_router: Callable for delivering webhooks
            conductor_stop: Conductor (graceful) stop for shutdown API call
            task_queue: An optional task queue for handlers
        """
        self.app = None
        self.admin_api_key = context.settings.get("admin.admin_api_key")
        self.admin_insecure_mode = bool(
            context.settings.get("admin.admin_insecure_mode")
        )
        self.host = host
        self.port = port
        self.conductor_stop = conductor_stop
        self.conductor_stats = conductor_stats
        self.loaded_modules = []
        self.task_queue = task_queue
        self.webhook_router = webhook_router
        self.websocket_queues = {}
        self.site = None

        self.context = context.start_scope("admin")
        self.responder = AdminResponder(
            self.context, outbound_message_router, self.send_webhook,
        )
        self.context.injector.bind_instance(BaseResponder, self.responder)

    async def make_application(self) -> web.Application:
        """Get the aiohttp application instance."""

        middlewares = [ready_middleware, debug_middleware, validation_middleware]

        # admin-token and admin-token are mutually exclusive and required.
        # This should be enforced during parameter parsing but to be sure,
        # we check here.
        assert self.admin_insecure_mode ^ bool(self.admin_api_key)

        def is_unprotected_path(path: str):
            return path in [
                "/api/doc",
                "/api/docs/swagger.json",
                "/favicon.ico",
                "/ws",  # ws handler checks authentication
            ] or path.startswith("/static/swagger/")

        # If admin_api_key is None, then admin_insecure_mode must be set so
        # we can safely enable the admin server with no security
        if self.admin_api_key:

            @web.middleware
            async def check_token(request, handler):
                header_admin_api_key = request.headers.get("x-api-key")
                valid_key = self.admin_api_key == header_admin_api_key

                if valid_key or is_unprotected_path(request.path):
                    return await handler(request)
                else:
                    raise web.HTTPUnauthorized()

            middlewares.append(check_token)

        collector: Collector = await self.context.inject(Collector, required=False)

        if self.task_queue:

            @web.middleware
            async def apply_limiter(request, handler):
                task = await self.task_queue.put(handler(request))
                return await task

            middlewares.append(apply_limiter)

        elif collector:

            @web.middleware
            async def collect_stats(request, handler):
                handler = collector.wrap_coro(handler, [handler.__qualname__])
                return await handler(request)

            middlewares.append(collect_stats)

        @web.middleware
        async def activate_wallet(request, handler):
            # TODO: Enable authentication in swagger docs page
            if request.path == '/api/doc' or 'swagger' in request.path:
                return await handler(request)
            if request.method == 'OPTIONS':
                return await handler(request)
            context = request.app["request_context"].copy()

            # For a custodial agent we need to inject the correct wallet into
            # the request
            ext_plugins = self.context.settings.get_value("external_plugins")
            if ext_plugins and 'aries_cloudagent.wallet_handler' in ext_plugins:

                wallet_handler: WalletHandler = await context.inject(WalletHandler)
                # TODO: Authorization concept.
                header_auth = request.headers.get("Wallet")
                if not header_auth:
                    raise web.HTTPUnauthorized()

                # Request instance and lock request of wallet provider so that
                # no other task can interfere
                #context.settings.set_value("wallet.id", header_auth)
                try:
                    await wallet_handler.set_instance(header_auth, context)
                except WalletNotFoundError:
                    raise web.HTTPUnauthorized(reason="Authorization not associated to any wallet instance.")

            request['context'] = context
            # Perform request.
            response = await handler(request)

            return response

        middlewares.append(activate_wallet)

        app = web.Application(middlewares=middlewares)
        app["request_context"] = self.context
        app["outbound_message_router"] = self.responder.send

        app.add_routes(
            [
                web.get("/", self.redirect_handler, allow_head=False),
                web.get("/plugins", self.plugins_handler, allow_head=False),
                web.get("/status", self.status_handler, allow_head=False),
                web.post("/status/reset", self.status_reset_handler),
                web.get("/status/live", self.liveliness_handler, allow_head=False),
                web.get("/status/ready", self.readiness_handler, allow_head=False),
                web.get("/shutdown", self.shutdown_handler, allow_head=False),
                web.get("/ws", self.websocket_handler, allow_head=False),
                web.get("/webhooks", self.webhooks_get_list_handler, allow_head=False),
                web.get("/webhooks/{webhook_id}", self.webhooks_get_handler, allow_head=False),
                web.post("/webhooks", self.webhooks_add_handler),
                web.delete("/webhooks/{webhook_id}", self.webhooks_remove_handler),
            ]
        )

        plugin_registry: PluginRegistry = await self.context.inject(
            PluginRegistry, required=False
        )
        if plugin_registry:
            await plugin_registry.register_admin_routes(app)

        cors = aiohttp_cors.setup(
            app,
            defaults={
                "*": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*",
                )
            },
        )
        for route in app.router.routes():
            cors.add(route)
        # get agent label
        agent_label = self.context.settings.get("default_label")
        version_string = f"v{__version__}"

        # if it is the agent in k8s behind the nginx ingress
        if agent_label == "ACA-Py Agent (Multi-Tenant)":
            setup_aiohttp_apispec(
                app=app, 
                title=agent_label, 
                version=version_string, 
                swagger_path="/agent/swagger-ui", 
                static_path="/agent/swagger-ui/static/swagger", 
                url="/agent/swagger-ui/swagger.json", 
                basePath="/agent/api",
                securityDefinitions={
                    "OAuth2": {"type": "apiKey", "name": "Authorization", "in": "header"}
                }, 
                security=[{"OAuth2": []}] 
        )
        else:
            setup_aiohttp_apispec(
                app=app, 
                title=agent_label, 
                version=version_string, 
                swagger_path="/api/doc",
                securityDefinitions={
                    "WalletAuth": {"type": "apiKey", "name": "Wallet", "in": "header"}
                },
                security=[{"WalletAuth": []}]
            )

        app.on_startup.append(self.on_startup)

        # ensure we always have status values
        app._state["ready"] = False
        app._state["alive"] = False

        return app

    async def start(self) -> None:
        """
        Start the webserver.

        Raises:
            AdminSetupError: If there was an error starting the webserver

        """
        self.app = await self.make_application()
        runner = web.AppRunner(self.app)
        await runner.setup()

        plugin_registry: PluginRegistry = await self.context.inject(
            PluginRegistry, required=False
        )
        if plugin_registry:
            plugin_registry.post_process_routes(self.app)

        # order tags alphabetically, parameters deterministically and pythonically
        swagger_dict = self.app._state["swagger_dict"]
        swagger_dict.get("tags", []).sort(key=lambda t: t["name"])
        for path in swagger_dict["paths"].values():
            for method_spec in path.values():
                method_spec["parameters"].sort(
                    key=lambda p: (p["in"], not p["required"], p["name"])
                )

        self.site = web.TCPSite(runner, host=self.host, port=self.port)

        try:
            await self.site.start()
            self.app._state["ready"] = True
            self.app._state["alive"] = True
        except OSError:
            raise AdminSetupError(
                "Unable to start webserver with host "
                + f"'{self.host}' and port '{self.port}'\n"
            )

    async def stop(self) -> None:
        """Stop the webserver."""
        self.app._state["ready"] = False  # in case call does not come through OpenAPI
        for queue in self.websocket_queues.values():
            queue.stop()
        if self.site:
            await self.site.stop()
            self.site = None

    async def on_startup(self, app: web.Application):
        """Perform webserver startup actions."""
        if self.admin_api_key:
            swagger = app["swagger_dict"]
            swagger["securityDefinitions"] = {
                "ApiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
            }
            swagger["security"] = [{"ApiKeyHeader": []}]

    @docs(tags=["server"], summary="Fetch the list of loaded plugins")
    @response_schema(AdminModulesSchema(), 200)
    async def plugins_handler(self, request: web.BaseRequest):
        """
        Request handler for the loaded plugins list.

        Args:
            request: aiohttp request object

        Returns:
            The module list response

        """
        registry: PluginRegistry = await self.context.inject(
            PluginRegistry, required=False
        )
        plugins = registry and sorted(registry.plugin_names) or []
        return web.json_response({"result": plugins})

    @docs(tags=["server"], summary="Fetch the server status")
    @response_schema(AdminStatusSchema(), 200)
    async def status_handler(self, request: web.BaseRequest):
        """
        Request handler for the server status information.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        status = {"version": __version__}
        status["label"] = self.context.settings.get("default_label")
        collector: Collector = await self.context.inject(Collector, required=False)
        if collector:
            status["timing"] = collector.results
        if self.conductor_stats:
            status["conductor"] = await self.conductor_stats()
        return web.json_response(status)

    @docs(tags=["server"], summary="Reset statistics")
    @response_schema(AdminStatusSchema(), 200)
    async def status_reset_handler(self, request: web.BaseRequest):
        """
        Request handler for resetting the timing statistics.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        collector: Collector = await self.context.inject(Collector, required=False)
        if collector:
            collector.reset()
        return web.json_response({})

    async def redirect_handler(self, request: web.BaseRequest):
        """Perform redirect to documentation."""
        raise web.HTTPFound("/api/doc")

    @docs(tags=["server"], summary="Liveliness check")
    @response_schema(AdminStatusLivelinessSchema(), 200)
    async def liveliness_handler(self, request: web.BaseRequest):
        """
        Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, always indicating True

        """
        app_live = self.app._state["alive"]
        if app_live:
            return web.json_response({"alive": app_live})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not available")

    @docs(tags=["server"], summary="Readiness check")
    @response_schema(AdminStatusReadinessSchema(), 200)
    async def readiness_handler(self, request: web.BaseRequest):
        """
        Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, indicating readiness for further calls

        """
        app_ready = self.app._state["ready"] and self.app._state["alive"]
        if app_ready:
            return web.json_response({"ready": app_ready})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not ready")

    @docs(tags=["server"], summary="Shut down server")
    async def shutdown_handler(self, request: web.BaseRequest):
        """
        Request handler for server shutdown.

        Args:
            request: aiohttp request object

        Returns:
            The web response (empty production)

        """
        self.app._state["ready"] = False
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.conductor_stop(), loop=loop)

        return web.json_response({})

    @docs(tags=["server"], summary="Get a list of webhook targets")
    @response_schema(WebhookTargetRecordListSchema(), 200)
    async def webhooks_get_list_handler(self, request: web.BaseRequest):
        """
        Request handler to get all webhook targets.

        Args:
            request: aiohttp request object.

        Returns:
            a list of webhook targets

        """
        context = request["context"]
        record_list = await self.get_webhook_target_list(context)

        results = []
        for record in record_list:
            record_dict = json.loads(record.value)
            record_dict["webhook_id"] = record.id
            results.append(record_dict)
        return web.json_response({"results": results})

    @docs(tags=["server"], summary="Get a webhook target.")
    @match_info_schema(WebhookIdMatchInfoSchema())
    @response_schema(WebhookTargetRecordSchema(), 200)
    async def webhooks_get_handler(self, request: web.BaseRequest):
        """
        Request handler to get a webhook target.

        Args:
            request: aiohttp request object.

        Returns:
            a webhook target

        """
        context = request["context"]
        webhook_id = request.match_info["webhook_id"]

        record = await self.get_webhook_target(context, webhook_id)
        if not record:
            raise web.HTTPBadRequest(reason="webhook target of specified webhook_id does not exists.")

        record_dict = json.loads(record.value)
        record_dict["webhook_id"] = record.id
        return web.json_response(record_dict)

    @docs(tags=["server"], summary="Add a new webhook target.")
    @request_schema(WebhookTargetSchema())
    @response_schema(WebhookTargetRecordSchema(), 201)
    async def webhooks_add_handler(self, request: web.BaseRequest):
        """
        Request handler for adding a new webhook target.

        Args:
            request: aiohttp request object

        Returns:
            a created webhook target

        """
        context = request["context"]
        body = await request.json()
        target_url = body.get("target_url")

        record = await self.add_webhook_target(context, target_url)
        if not record:
            raise web.HTTPBadRequest(reason="webhook target of specified target_url already exists.")

        record_dict = json.loads(record.value)
        record_dict["webhook_id"] = record.id
        return web.json_response(record_dict, status=201)

    @docs(tags=["server"], summary="Remove a webhook target.")
    @match_info_schema(WebhookIdMatchInfoSchema())
    async def webhooks_remove_handler(self, request: web.BaseRequest):
        """
        Request handler for removing a webhook target.

        Args:
            request: aiohttp request object

        Returns:

        """
        context = request["context"]
        webhook_id = request.match_info["webhook_id"]

        result = await self.remove_webhook_target(context, webhook_id)
        if not result:
            raise web.HTTPBadRequest(reason="webhook target of specified webhook_id does not exists.")

        return web.Response(status=204)

    def notify_fatal_error(self):
        """Set our readiness flags to force a restart (openshift)."""
        LOGGER.error("Received shutdown request notify_fatal_error()")
        self.app._state["ready"] = False
        self.app._state["alive"] = False

    async def websocket_handler(self, request):
        """Send notifications to admin client over websocket."""

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        socket_id = str(uuid.uuid4())
        queue = BasicMessageQueue()
        loop = asyncio.get_event_loop()

        if self.admin_insecure_mode:
            # open to send websocket messages without api key auth
            queue.authenticated = True
        else:
            header_admin_api_key = request.headers.get("x-api-key")
            # authenticated via http header?
            queue.authenticated = header_admin_api_key == self.admin_api_key

        try:
            self.websocket_queues[socket_id] = queue
            await queue.enqueue(
                {
                    "topic": "settings",
                    "payload": {
                        "authenticated": queue.authenticated,
                        "label": self.context.settings.get("default_label"),
                        "endpoint": self.context.settings.get("default_endpoint"),
                        "no_receive_invites": self.context.settings.get(
                            "admin.no_receive_invites", False
                        ),
                        "help_link": self.context.settings.get("admin.help_link"),
                    },
                }
            )

            closed = False
            receive = loop.create_task(ws.receive_json())
            send = loop.create_task(queue.dequeue(timeout=5.0))

            while not closed:
                try:
                    await asyncio.wait(
                        (receive, send), return_when=asyncio.FIRST_COMPLETED
                    )
                    if ws.closed:
                        closed = True

                    if receive.done():
                        if not closed:
                            msg_received = None
                            msg_api_key = None
                            try:
                                # this call can re-raise exeptions from inside the task
                                msg_received = receive.result()
                                msg_api_key = msg_received.get("x-api-key")
                            except Exception:
                                LOGGER.exception(
                                    "Exception in websocket receiving task:"
                                )
                            if self.admin_api_key and self.admin_api_key == msg_api_key:
                                # authenticated via websocket message
                                queue.authenticated = True

                            receive = loop.create_task(ws.receive_json())

                    if send.done():
                        try:
                            msg = send.result()
                        except asyncio.TimeoutError:
                            msg = None

                        if msg is None:
                            # we send fake pings because the JS client
                            # can't detect real ones
                            msg = {
                                "topic": "ping",
                                "authenticated": queue.authenticated,
                            }
                        if not closed:
                            if msg:
                                await ws.send_json(msg)
                            send = loop.create_task(queue.dequeue(timeout=5.0))

                except asyncio.CancelledError:
                    closed = True

            if not receive.done():
                receive.cancel()
            if not send.done():
                send.cancel()

        finally:
            del self.websocket_queues[socket_id]

        return ws

    async def get_webhook_target_list(self, context: InjectionContext):
        """Get a list of webhook targets."""

        storage = await context.inject(BaseStorage)
        record_list = await storage.search_records(
            type_filter=WEBHOOK_SENT_RECORD_TYPE,
        ).fetch_all()

        return record_list

    async def get_webhook_target(self, context: InjectionContext, webhook_id: str):
        """Get a webhook target."""

        storage = await context.inject(BaseStorage)
        try:
            record = await storage.get_record(
                record_type=WEBHOOK_SENT_RECORD_TYPE,
                record_id=webhook_id,
            )
        except StorageNotFoundError:
            return None

        return record

    async def add_webhook_target(
        self,
        context: InjectionContext,
        target_url: str,
        topic_filter: Sequence[str] = None,
        max_attempts: int = None,
    ):
        """Add a webhook target."""

        storage: BaseStorage = await context.inject(BaseStorage)
        try:
            result = await storage.search_records(
                type_filter=WEBHOOK_SENT_RECORD_TYPE,
                tag_query={"target_url": target_url},
            ).fetch_single()
            if result:
                return None
        except StorageNotFoundError:
            pass

        webhook_target = WebhookTarget(target_url, topic_filter, max_attempts)
        record = StorageRecord(
            type=WEBHOOK_SENT_RECORD_TYPE,
            value=webhook_target.to_json(),
            tags={"target_url": target_url},
            id=str(uuid.uuid4())
        )
        await storage.add_record(record)
        return record

    async def remove_webhook_target(self, context: InjectionContext, webhook_id: str):
        """Remove a webhook target."""

        storage: BaseStorage = await context.inject(BaseStorage)
        try:
            record = await storage.get_record(
                record_type=WEBHOOK_SENT_RECORD_TYPE,
                record_id=webhook_id,
            )
            if record:
                await storage.delete_record(record)
        except StorageNotFoundError:
            return False

        return True

    async def send_webhook(self, context: InjectionContext, topic: str, payload: dict):
        """Add a webhook to the queue, to send to all registered targets."""
        if self.webhook_router:
            storage = await context.inject(BaseStorage)
            found = await storage.search_records(
                type_filter=WEBHOOK_SENT_RECORD_TYPE,
            ).fetch_all()
            for record in found:
                target = WebhookTarget.from_json(record.value)
                if not target.topic_filter or topic in target.topic_filter:
                    self.webhook_router(
                        topic, payload, target.target_url, target.max_attempts
                    )

        for queue in self.websocket_queues.values():
            if queue.authenticated or topic in ("ping", "settings"):
                await queue.enqueue({"topic": topic, "payload": payload})
