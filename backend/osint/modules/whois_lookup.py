"""WHOIS / Domain lookup."""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class WhoisLookup(OSINTModule):
    name = "WHOIS Lookup"
    description = "Search for domains potentially owned by user"

    # Common free email providers to skip
    FREE_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'icloud.com', 'aol.com', 'protonmail.com', 'mail.com',
        'live.com', 'msn.com', 'ymail.com', 'proton.me',
    }

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Look for domains associated with email."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        local, domain = email.split('@', 1)

        # Check if custom domain (not free provider)
        if domain not in self.FREE_PROVIDERS:
            yield Finding(
                id=str(uuid.uuid4()),
                type=NodeType.DOMAIN,
                severity=Severity.MEDIUM,
                title=f"Custom Domain: {domain}",
                description="Email uses custom domain (may be owned by user)",
                source="Email Analysis",
                source_url=f"https://{domain}",
                timestamp=datetime.utcnow(),
                data={
                    "domain": domain,
                    "type": "custom_email_domain",
                },
                parent_id=parent_id,
                link_label="email domain",
            )

        # Check potential personal domains
        potential_domains = []

        # Username-based domains
        username = local.replace('.', '').replace('_', '').replace('-', '')
        for tld in ['.com', '.net', '.org', '.io', '.dev', '.me']:
            potential_domains.append(f"{username}{tld}")

        # Also try with common patterns
        if '.' in local:
            parts = local.split('.')
            if len(parts) == 2:
                # john.doe -> johndoe.com, doedev.com
                potential_domains.append(f"{parts[0]}{parts[1]}.com")
                potential_domains.append(f"{parts[1]}dev.com")

        # Check if domains resolve (basic DNS check)
        async with httpx.AsyncClient() as client:
            for domain_to_check in potential_domains[:8]:  # Limit checks
                try:
                    # Use Google DNS API for checking
                    resp = await client.get(
                        f"https://dns.google/resolve?name={domain_to_check}&type=A",
                        timeout=3.0,
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("Answer"):
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.DOMAIN,
                                severity=Severity.MEDIUM,
                                title=f"Domain: {domain_to_check}",
                                description="Potentially associated domain (active)",
                                source="DNS Lookup",
                                source_url=f"https://{domain_to_check}",
                                timestamp=datetime.utcnow(),
                                data={
                                    "domain": domain_to_check,
                                    "status": "active",
                                    "type": "potential_personal",
                                },
                                parent_id=parent_id,
                                link_label="may own",
                            )
                except Exception:
                    pass
