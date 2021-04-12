"""Interfaces and base classes for DID Resolution."""

import logging

from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from .did_resolver_registry import DIDResolverRegistry

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Set up default resolvers."""
    registry = context.inject(DIDResolverRegistry, required=False)
    if not registry:
        LOGGER.warning("No DID Resolver Registry instance found in context")
        return

    if context.settings.get("ledger.disabled"):
        LOGGER.warning("Ledger is not configured, not loading IndyDIDResolver")
        return

    resolver = ClassProvider(
        "aries_cloudagent.resolver.default.indy.IndyDIDResolver"
    ).provide(context.settings, context.injector)
    await resolver.setup(context)
    registry.register(resolver)
