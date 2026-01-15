"""Base class for OSINT modules."""

from abc import ABC, abstractmethod
from typing import AsyncGenerator
from models.findings import Finding


class OSINTModule(ABC):
    """
    Base interface for all OSINT modules.

    Each module:
    - Takes a seed (email, username, etc.)
    - Yields Finding objects as they're discovered
    - Handles its own errors gracefully
    - Respects rate limits
    """

    name: str = "Base Module"
    description: str = "Base OSINT module"

    @abstractmethod
    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Execute the OSINT lookup.

        Args:
            seed: Input to search (email, username, etc.)
            depth: Current scan depth
            parent_id: ID of parent finding (for graph edges)

        Yields:
            Finding objects as discovered
        """
        pass
