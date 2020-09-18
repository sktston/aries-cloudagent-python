"""Message type identifiers for Feature Discovery."""

from ...didcomm_prefix import DIDCommPrefix

SPEC_URI = (
    "https://github.com/hyperledger/aries-rfcs/tree/"
    "9b7ab9814f2e7d1108f74aca6f3d2e5d62899473/features/0031-discover-features"
)

# Message types
DISCLOSE = f"discover-features/1.0/disclose"
QUERY = f"discover-features/1.0/query"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.discovery.v1_0"

MESSAGE_TYPES = {
    **{
        pfx.qualify(DISCLOSE): (f"{PROTOCOL_PACKAGE}.messages.disclose.Disclose")
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(QUERY): (f"{PROTOCOL_PACKAGE}.messages.query.Query")
        for pfx in DIDCommPrefix
    },
}
