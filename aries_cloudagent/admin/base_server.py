"""Abstract admin server interface."""


from abc import ABC, abstractmethod
from typing import Sequence

from aries_cloudagent.config.injection_context import InjectionContext


class BaseAdminServer(ABC):
    """Admin HTTP server class."""

    @abstractmethod
    async def start(self) -> None:
        """
        Start the webserver.

        Raises:
            AdminSetupError: If there was an error starting the webserver

        """

    @abstractmethod
    async def stop(self) -> None:
        """Stop the webserver."""

    @abstractmethod
    async def get_webhook_target_list(self, context: InjectionContext):
        """Get a list of webhook targets."""

    @abstractmethod
    async def get_webhook_target(self, context: InjectionContext, webhook_id: str):
        """Get a webhook target."""

    @abstractmethod
    async def add_webhook_target(
        self,
        context: InjectionContext,
        target_url: str,
        topic_filter: Sequence[str] = None,
        max_attempts: int = None,
    ):
        """Add a webhook target."""

    @abstractmethod
    async def remove_webhook_target(self, context: InjectionContext, webhook_id: str):
        """Remove a webhook target."""

    @abstractmethod
    async def send_webhook(self, topic: str, payload: dict):
        """Add a webhook to the queue, to send to all registered targets."""
