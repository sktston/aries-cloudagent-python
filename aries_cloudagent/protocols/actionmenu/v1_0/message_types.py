"""Message type identifiers for Action Menus."""

from ...didcomm_prefix import DIDCommPrefix

# Message types
MENU = f"action-menu/1.0/menu"
MENU_REQUEST = f"action-menu/1.0/menu-request"
PERFORM = f"action-menu/1.0/perform"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.actionmenu.v1_0"

MESSAGE_TYPES = {
    **{
        pfx.qualify(MENU): f"{PROTOCOL_PACKAGE}.messages.menu.Menu"
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(MENU_REQUEST): (
            f"{PROTOCOL_PACKAGE}.messages.menu_request.MenuRequest"
        )
        for pfx in DIDCommPrefix
    },
    **{
        pfx.qualify(PERFORM): f"{PROTOCOL_PACKAGE}.messages.perform.Perform"
        for pfx in DIDCommPrefix
    },
}

CONTROLLERS = {
    pfx.qualify("action-menu/1.0"): f"{PROTOCOL_PACKAGE}.controller.Controller"
    for pfx in DIDCommPrefix
}
