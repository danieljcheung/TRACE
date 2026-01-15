"""
Reverse email lookup - finds personal info from email address.
Uses free OSINT APIs and services.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class ReverseLookup(OSINTModule):
    name = "Reverse Email Lookup"
    description = "Find personal information from email address"

    def __init__(self):
        self.timeout = 15.0

    async def _check_emailrep(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check EmailRep.io for email reputation and info."""
        try:
            resp = await client.get(
                f"https://emailrep.io/{email}",
                headers={
                    "User-Agent": "TRACE-OSINT",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                return resp.json()

        except Exception as e:
            print(f"[ReverseLookup] EmailRep error: {e}")

        return None

    async def _check_hunter(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check Hunter.io for email verification (limited free)."""
        try:
            # Hunter has a free verify endpoint (limited)
            resp = await client.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email},
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {})

        except Exception:
            pass

        return None

    async def _check_disify(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check Disify for disposable email detection and info."""
        try:
            resp = await client.get(
                f"https://disify.com/api/email/{email}",
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                return resp.json()

        except Exception:
            pass

        return None

    async def _check_thatsthem(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Try ThatsThem email lookup (may have rate limits)."""
        try:
            resp = await client.get(
                f"https://thatsthem.com/email/{email}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html",
                },
                timeout=self.timeout,
                follow_redirects=True,
            )

            if resp.status_code == 200:
                html = resp.text

                # Try to extract any visible info
                result = {}

                # Look for name
                name_match = re.search(r'<h2[^>]*class="[^"]*name[^"]*"[^>]*>([^<]+)</h2>', html)
                if name_match:
                    result["name"] = name_match.group(1).strip()

                # Look for location
                loc_match = re.search(r'<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>', html)
                if loc_match:
                    result["location"] = loc_match.group(1).strip()

                # Check if any results found
                if "No results found" not in html and result:
                    return result

        except Exception:
            pass

        return None

    async def _extract_name_from_email(self, email: str) -> dict | None:
        """Try to extract name from email format."""
        local = email.split('@')[0].lower()

        # Common patterns
        patterns = [
            # firstname.lastname
            r'^([a-z]+)\.([a-z]+)$',
            # firstnamelastname
            r'^([a-z]{2,})([a-z]{2,})$',
            # firstname_lastname
            r'^([a-z]+)_([a-z]+)$',
            # first initial + lastname
            r'^([a-z])([a-z]{3,})$',
        ]

        for pattern in patterns[:1]:  # Just the most reliable one
            match = re.match(pattern, local)
            if match:
                parts = match.groups()
                if len(parts) == 2:
                    first = parts[0].title()
                    last = parts[1].title()
                    # Filter out obvious non-names
                    if len(first) > 1 and len(last) > 2:
                        return {
                            "first_name": first,
                            "last_name": last,
                            "confidence": "low",
                        }

        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Perform reverse email lookup."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            # EmailRep.io - reputation and profile info
            emailrep = await self._check_emailrep(client, email)

            if emailrep:
                reputation = emailrep.get("reputation", "unknown")
                suspicious = emailrep.get("suspicious", False)
                details = emailrep.get("details", {})
                profiles = details.get("profiles", [])

                # Reputation finding
                severity = Severity.CRITICAL if suspicious else Severity.MEDIUM if reputation == "low" else Severity.LOW

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=severity,
                    title=f"Email Reputation: {reputation.title()}",
                    description=f"{'SUSPICIOUS - may be compromised' if suspicious else 'Email reputation assessment'}",
                    source="EmailRep.io",
                    source_url="https://emailrep.io",
                    timestamp=datetime.utcnow(),
                    data={
                        "reputation": reputation,
                        "suspicious": suspicious,
                        "blacklisted": details.get("blacklisted", False),
                        "data_breach": details.get("data_breach", False),
                        "malicious_activity": details.get("malicious_activity", False),
                        "spam": details.get("spam", False),
                        "free_provider": details.get("free_provider", True),
                        "deliverable": details.get("deliverable", True),
                    },
                    parent_id=parent_id,
                    link_label="reputation",
                )

                # Social profiles found
                if profiles:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"Social Profiles: {', '.join(profiles[:5])}",
                        description=f"Email associated with {len(profiles)} platform(s)",
                        source="EmailRep.io",
                        timestamp=datetime.utcnow(),
                        data={
                            "profiles": profiles,
                            "count": len(profiles),
                        },
                        parent_id=parent_id,
                        link_label="profiles on",
                    )

                # Data breach indicator
                if details.get("data_breach"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.HIGH,
                        title="Data Breach Indicator",
                        description="Email has appeared in known data breaches",
                        source="EmailRep.io",
                        timestamp=datetime.utcnow(),
                        data={
                            "breach_detected": True,
                            "remediation": "Change passwords for all accounts using this email",
                        },
                        parent_id=parent_id,
                        link_label="breached",
                    )

                # Credentials leaked indicator
                if details.get("credentials_leaked"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.CRITICAL,
                        title="Credentials Leaked",
                        description="Username/password combinations have been leaked",
                        source="EmailRep.io",
                        timestamp=datetime.utcnow(),
                        data={
                            "credentials_leaked": True,
                            "remediation": "URGENT: Change all passwords immediately",
                        },
                        parent_id=parent_id,
                        link_label="credentials leaked",
                    )

            import asyncio
            await asyncio.sleep(1)

            # Disify - disposable email check
            disify = await self._check_disify(client, email)

            if disify:
                is_disposable = disify.get("disposable", False)
                if is_disposable:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.LOW,
                        title="Disposable Email Detected",
                        description="This is a temporary/disposable email address",
                        source="Disify",
                        timestamp=datetime.utcnow(),
                        data={
                            "disposable": True,
                            "dns": disify.get("dns", True),
                            "format": disify.get("format", True),
                        },
                        parent_id=parent_id,
                        link_label="is disposable",
                    )

            await asyncio.sleep(1)

            # ThatsThem lookup
            thatsthem = await self._check_thatsthem(client, email)

            if thatsthem:
                if thatsthem.get("name"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Name Found: {thatsthem['name']}",
                        description="Real name found via reverse lookup",
                        source="ThatsThem",
                        source_url=f"https://thatsthem.com/email/{email}",
                        timestamp=datetime.utcnow(),
                        data={
                            "name": thatsthem["name"],
                            "source": "reverse_lookup",
                            "remediation": "Request removal from ThatsThem",
                        },
                        parent_id=parent_id,
                        link_label="name is",
                    )

                if thatsthem.get("location"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Location Found: {thatsthem['location']}",
                        description="Location found via reverse lookup",
                        source="ThatsThem",
                        source_url=f"https://thatsthem.com/email/{email}",
                        timestamp=datetime.utcnow(),
                        data={
                            "location": thatsthem["location"],
                            "source": "reverse_lookup",
                        },
                        parent_id=parent_id,
                        link_label="located in",
                    )

            # Try name extraction from email format
            name_guess = await self._extract_name_from_email(email)
            if name_guess:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.LOW,
                    title=f"Possible Name: {name_guess['first_name']} {name_guess['last_name']}",
                    description="Name pattern detected in email address",
                    source="Email Analysis",
                    timestamp=datetime.utcnow(),
                    data={
                        **name_guess,
                        "note": "Inferred from email format - may not be accurate",
                    },
                    parent_id=parent_id,
                    link_label="possibly named",
                )
