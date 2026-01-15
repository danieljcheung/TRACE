"""Extract potential usernames from email address."""

import re
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class UsernameExtractor(OSINTModule):
    name = "Username Extractor"
    description = "Extract potential usernames from email"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Extract usernames from email prefix."""

        if '@' not in seed:
            return

        local = seed.split('@')[0].lower()
        usernames = set()

        # Original
        usernames.add(local)

        # Remove dots: john.doe -> johndoe
        usernames.add(local.replace('.', ''))

        # Dots to underscores: john.doe -> john_doe
        usernames.add(local.replace('.', '_'))

        # Split on separators
        for sep in ['.', '_', '-']:
            parts = local.split(sep)
            if len(parts) > 1:
                usernames.add(''.join(parts))
                usernames.add('_'.join(parts))
                # First initial + last: jdoe
                if len(parts) == 2:
                    usernames.add(parts[0][0] + parts[1])

        # Remove trailing numbers (birth year, etc.)
        cleaned = re.sub(r'\d+$', '', local)
        if cleaned and cleaned != local and len(cleaned) >= 3:
            usernames.add(cleaned)

        # Filter: 3-30 chars, alphanumeric + underscore only
        usernames = {
            u for u in usernames
            if 3 <= len(u) <= 30 and re.match(r'^[a-z0-9_]+$', u)
        }

        for username in sorted(usernames):
            yield Finding(
                id=str(uuid.uuid4()),
                type=NodeType.USERNAME,
                severity=Severity.LOW,
                title=f"Username: {username}",
                description="Potential username extracted from email",
                source="Email Analysis",
                timestamp=datetime.utcnow(),
                data={"username": username},
                parent_id=parent_id,
                link_label="username from",
            )
