"""
the did resolver.

responsible for keeping track of all resolvers. more importantly
retrieving did's from different sources provided by the method type.
"""

import logging
from itertools import chain
from typing import Union

from pydid import DID, DIDDocument, DIDError, DIDUrl, Service, VerificationMethod

from ..core.profile import Profile

from .base import (
    BaseDIDResolver,
    DIDMethodNotSupported,
    DIDNotFound,
    ResolverError,
)
from .did_resolver_registry import DIDResolverRegistry

LOGGER = logging.getLogger(__name__)


class DIDResolver:
    """did resolver singleton."""

    def __init__(self, registry: DIDResolverRegistry):
        """Initialize a `didresolver` instance."""
        self.did_resolver_registry = registry

    async def resolve(self, profile: Profile, did: Union[str, DID]) -> DIDDocument:
        """Retrieve did doc from public registry."""
        # TODO Cache results
        py_did = DID(did) if isinstance(did, str) else did
        for resolver in self._match_did_to_resolver(py_did):
            try:
                LOGGER.debug("Resolving DID %s with %s", did, resolver)
                return await resolver.resolve(profile, py_did)
            except DIDNotFound:
                LOGGER.debug("DID %s not found by resolver %s", did, resolver)

        raise DIDNotFound(f"DID {did} could not be resolved")

    def _match_did_to_resolver(self, py_did: DID) -> BaseDIDResolver:
        """Generate supported DID Resolvers.

        Native resolvers are yielded first, in registered order followed by
        non-native resolvers in registered order.
        """
        valid_resolvers = list(
            filter(
                lambda resolver: resolver.supports(py_did.method),
                self.did_resolver_registry.resolvers,
            )
        )
        native_resolvers = filter(lambda resolver: resolver.native, valid_resolvers)
        non_native_resolvers = filter(
            lambda resolver: not resolver.native, valid_resolvers
        )
        resolvers = list(chain(native_resolvers, non_native_resolvers))
        if not resolvers:
            raise DIDMethodNotSupported(f"DID method '{py_did.method}' not supported")
        return resolvers

    async def dereference(
        self, profile: Profile, did_url: str
    ) -> Union[Service, VerificationMethod]:
        """Dereference a DID URL to its corresponding DID Doc object."""
        # TODO Use cached DID Docs when possible
        try:
            did_url = DIDUrl.parse(did_url)
            doc = await self.resolve(profile, did_url.did)
            return doc.dereference(did_url)
        except DIDError as err:
            raise ResolverError(
                "Failed to parse DID URL from {}".format(did_url)
            ) from err
