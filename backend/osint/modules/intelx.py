"""
IntelX (Intelligence X) Search - Search leaked databases and paste sites.
Free tier: 10 searches/day.
Returns email:username:password combos from breaches.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class IntelXSearch(OSINTModule):
    name = "IntelX Search"
    description = "Search leaked databases and paste sites"

    # IntelX free API endpoints
    PHONEBOOK_URL = "https://2.intelx.io/phonebook/search"
    SEARCH_URL = "https://2.intelx.io/intelligent/search"

    def __init__(self):
        self.timeout = 20.0

    def _extract_usernames_from_text(self, text: str) -> list[str]:
        """Extract potential usernames from leak text."""
        usernames = set()

        # Common patterns in leaked data
        patterns = [
            # username:password or username:hash
            r'([a-zA-Z0-9_.-]{3,30}):[\w\$\.\/]{6,}',
            # user=username
            r'user(?:name)?[=:]\s*([a-zA-Z0-9_.-]{3,30})',
            # login: username
            r'login[=:\s]+([a-zA-Z0-9_.-]{3,30})',
            # @ mentions
            r'@([a-zA-Z0-9_]{3,30})',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Filter out obvious non-usernames
                if match.lower() not in ['password', 'admin', 'user', 'login', 'email', 'null', 'undefined']:
                    if not re.match(r'^[\d.]+$', match):  # Not just numbers/IPs
                        usernames.add(match)

        return list(usernames)[:20]  # Limit to prevent spam

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search IntelX for leaked data containing the email."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            discovered_usernames = set()
            total_results = 0

            # Try phonebook search (aggregated results)
            try:
                resp = await client.get(
                    self.PHONEBOOK_URL,
                    params={
                        "term": email,
                        "maxresults": 100,
                        "media": 0,
                        "target": 1,  # Email target
                        "timeout": 10,
                    },
                    headers={"User-Agent": "TRACE-OSINT"},
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()

                    # Check for search ID to get results
                    search_id = data.get("id")
                    if search_id:
                        # Wait a moment then fetch results
                        import asyncio
                        await asyncio.sleep(2)

                        results_resp = await client.get(
                            f"https://2.intelx.io/phonebook/search/result",
                            params={"id": search_id, "limit": 100},
                            headers={"User-Agent": "TRACE-OSINT"},
                            timeout=self.timeout,
                        )

                        if results_resp.status_code == 200:
                            results = results_resp.json()
                            selectors = results.get("selectors", [])
                            total_results = len(selectors)

                            for selector in selectors[:50]:
                                selectorvalue = selector.get("selectorvalue", "")
                                selectortype = selector.get("selectortypeh", "")

                                # Extract usernames from different selector types
                                if selectortype in ["Username", "User"]:
                                    if selectorvalue and selectorvalue != email:
                                        discovered_usernames.add(selectorvalue)

                                # Try to extract usernames from combined fields
                                usernames = self._extract_usernames_from_text(selectorvalue)
                                discovered_usernames.update(usernames)

            except Exception as e:
                print(f"[IntelX] Phonebook search error: {e}")

            # Try intelligent search for paste/leak content
            try:
                resp = await client.post(
                    self.SEARCH_URL,
                    json={
                        "term": email,
                        "maxresults": 50,
                        "media": 0,
                        "sort": 2,  # By date
                        "terminate": [],
                    },
                    headers={
                        "User-Agent": "TRACE-OSINT",
                        "Content-Type": "application/json",
                    },
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    search_id = data.get("id")

                    if search_id:
                        import asyncio
                        await asyncio.sleep(3)

                        results_resp = await client.get(
                            f"https://2.intelx.io/intelligent/search/result",
                            params={"id": search_id},
                            headers={"User-Agent": "TRACE-OSINT"},
                            timeout=self.timeout,
                        )

                        if results_resp.status_code == 200:
                            results = results_resp.json()
                            records = results.get("records", [])

                            if records:
                                total_results = max(total_results, len(records))

                                # Analyze records for usernames
                                for record in records[:20]:
                                    name = record.get("name", "")
                                    if name:
                                        usernames = self._extract_usernames_from_text(name)
                                        discovered_usernames.update(usernames)

            except Exception as e:
                print(f"[IntelX] Intelligent search error: {e}")

            # Remove the email itself and email prefix from discovered usernames
            email_prefix = email.split('@')[0]
            discovered_usernames.discard(email)
            discovered_usernames.discard(email_prefix)

            # Yield findings for discovered usernames
            for username in list(discovered_usernames)[:10]:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.USERNAME,
                    severity=Severity.HIGH,
                    title=f"Username Discovered: {username}",
                    description="Found in leaked database records",
                    source="IntelX",
                    source_url="https://intelx.io",
                    timestamp=datetime.utcnow(),
                    data={
                        "username": username,
                        "discovery_method": "intelx_leak_search",
                        "confidence": "medium",
                        "note": "Extracted from breach/paste data",
                    },
                    parent_id=parent_id,
                    link_label="discovered username",
                )

            # Summary finding
            if total_results > 0:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.HIGH,
                    title=f"IntelX: {total_results} Records Found",
                    description=f"Email found in leaked databases/paste sites",
                    source="IntelX",
                    source_url=f"https://intelx.io/?s={email}",
                    timestamp=datetime.utcnow(),
                    data={
                        "total_records": total_results,
                        "discovered_usernames": list(discovered_usernames),
                        "remediation": "Check for leaked credentials; change passwords",
                    },
                    parent_id=parent_id,
                    link_label="found in",
                )
            elif discovered_usernames:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.MEDIUM,
                    title=f"IntelX: {len(discovered_usernames)} Usernames Discovered",
                    description="Associated usernames found in leak data",
                    source="IntelX",
                    timestamp=datetime.utcnow(),
                    data={
                        "usernames": list(discovered_usernames),
                    },
                    parent_id=parent_id,
                    link_label="usernames found",
                )
