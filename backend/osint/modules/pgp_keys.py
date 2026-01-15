"""PGP keyserver lookup."""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class PGPKeysLookup(OSINTModule):
    name = "PGP Keys"
    description = "Search PGP keyservers for public keys"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search PGP keyservers for email."""

        email = seed.lower().strip()

        async with httpx.AsyncClient() as client:
            # Try keys.openpgp.org first (modern, clean API)
            try:
                resp = await client.get(
                    f"https://keys.openpgp.org/vks/v1/by-email/{email}",
                    timeout=10.0,
                )

                if resp.status_code == 200:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.LOW,
                        title="PGP Key (OpenPGP)",
                        description="Public PGP key registered with this email",
                        source="keys.openpgp.org",
                        source_url=f"https://keys.openpgp.org/search?q={email}",
                        timestamp=datetime.utcnow(),
                        data={
                            "keyserver": "keys.openpgp.org",
                            "email": email,
                        },
                        parent_id=parent_id,
                        link_label="has PGP key",
                    )
            except Exception:
                pass

            # Try Ubuntu keyserver (SKS pool)
            try:
                resp = await client.get(
                    f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index",
                    timeout=10.0,
                )

                if resp.status_code == 200 and "pub" in resp.text.lower():
                    # Extract key IDs
                    key_ids = re.findall(r'([A-Fa-f0-9]{8,16})', resp.text)
                    key_ids = list(set(key_ids))[:3]  # Dedupe, limit to 3

                    if key_ids:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.LOW,
                            title="PGP Key (SKS)",
                            description=f"Key ID(s): {', '.join(key_ids)}",
                            source="Ubuntu Keyserver",
                            source_url=f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index",
                            timestamp=datetime.utcnow(),
                            data={
                                "keyserver": "keyserver.ubuntu.com",
                                "key_ids": key_ids,
                            },
                            parent_id=parent_id,
                            link_label="has PGP key",
                        )
            except Exception:
                pass

            # Try MIT keyserver
            try:
                resp = await client.get(
                    f"https://pgp.mit.edu/pks/lookup?search={email}&op=index",
                    timeout=10.0,
                )

                if resp.status_code == 200 and "pub" in resp.text.lower():
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.LOW,
                        title="PGP Key (MIT)",
                        description="Public key found on MIT keyserver",
                        source="MIT PGP Keyserver",
                        source_url=f"https://pgp.mit.edu/pks/lookup?search={email}&op=index",
                        timestamp=datetime.utcnow(),
                        data={
                            "keyserver": "pgp.mit.edu",
                        },
                        parent_id=parent_id,
                        link_label="has PGP key",
                    )
            except Exception:
                pass
