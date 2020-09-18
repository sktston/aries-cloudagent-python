"""Message and inner object type identifiers for Out of Band messages."""

from ...didcomm_prefix import DIDCommPrefix

SPEC_URI = (
    "https://github.com/hyperledger/aries-rfcs/tree/"
    "2da7fc4ee043effa3a9960150e7ba8c9a4628b68/features/0434-outofband"
)

# Message types
INVITATION = f"out-of-band/1.0/invitation"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.out_of_band.v1_0"

MESSAGE_TYPES = {
    pfx.qualify(INVITATION): f"{PROTOCOL_PACKAGE}.messages.invitation.Invitation"
    for pfx in DIDCommPrefix
}
