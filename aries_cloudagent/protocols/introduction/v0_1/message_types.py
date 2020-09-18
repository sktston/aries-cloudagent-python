"""Message type identifiers for Introductions."""

from ...didcomm_prefix import DIDCommPrefix

INVITATION_REQUEST = f"introduction-service/0.1/invitation-request"
INVITATION = f"introduction-service/0.1/invitation"
FORWARD_INVITATION = f"introduction-service/0.1/forward-invitation"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.introduction.v0_1"

MESSAGE_TYPES = {
    **{
        pfx.qualify(INVITATION_REQUEST): (
            f"{PROTOCOL_PACKAGE}.messages.invitation_request.InvitationRequest"
        )
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(INVITATION): (f"{PROTOCOL_PACKAGE}.messages.invitation.Invitation")
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(FORWARD_INVITATION): (
            f"{PROTOCOL_PACKAGE}.messages.forward_invitation.ForwardInvitation"
        )
        for pfx in DIDCommPrefix
    },
}
