"""Message type identifiers for Routing."""

from ...didcomm_prefix import DIDCommPrefix

# Message types
FORWARD = f"routing/1.0/forward"
ROUTE_QUERY_REQUEST = f"routing/1.0/route-query-request"
ROUTE_QUERY_RESPONSE = f"routing/1.0/route-query-response"
ROUTE_UPDATE_REQUEST = f"routing/1.0/route-update-request"
ROUTE_UPDATE_RESPONSE = f"routing/1.0/route-update-response"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.routing.v1_0"

MESSAGE_TYPES = {
    **{
        pfx.qualify(FORWARD): f"{PROTOCOL_PACKAGE}.messages.forward.Forward"
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(ROUTE_QUERY_REQUEST): (
            f"{PROTOCOL_PACKAGE}.messages.route_query_request.RouteQueryRequest"
        )
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(ROUTE_QUERY_RESPONSE): (
            f"{PROTOCOL_PACKAGE}.messages.route_query_response.RouteQueryResponse"
        )
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(ROUTE_UPDATE_REQUEST): (
            f"{PROTOCOL_PACKAGE}.messages.route_update_request.RouteUpdateRequest"
        )
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(ROUTE_UPDATE_RESPONSE): (
            f"{PROTOCOL_PACKAGE}.messages.route_update_response.RouteUpdateResponse"
        )
        for pfx in DIDCommPrefix
    },
}
