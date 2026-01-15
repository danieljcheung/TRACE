"""
Paste site searcher - searches for email in paste/leak sites.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class PasteSearch(OSINTModule):
    name = "Paste Site Search"
    description = "Search paste and leak sites for email exposure"

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

    async def _search_github_gists(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> list[dict]:
        """Search GitHub Gists for email."""
        results = []

        try:
            # GitHub code search API
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": f'"{email}"'},
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "TRACE-OSINT",
                },
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", [])[:10]:
                    results.append({
                        "url": item.get("html_url", ""),
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "path": item.get("path", ""),
                        "source": "GitHub Code",
                    })

        except Exception as e:
            print(f"[PasteSearch] GitHub error: {e}")

        return results

    async def _search_intelx(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Search Intelligence X for email (free tier)."""
        try:
            # IntelX phonebook search (free)
            resp = await client.get(
                "https://2.intelx.io/phonebook/search",
                params={
                    "term": email,
                    "buckets": [],
                    "lookuplevel": 0,
                    "maxresults": 10,
                    "timeout": 5,
                    "datefrom": "",
                    "dateto": "",
                    "sort": 2,
                    "media": 0,
                    "terminate": [],
                },
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("records"):
                    return {
                        "found": True,
                        "records": data.get("records", 0),
                        "sources": data.get("selectors", [])[:5],
                    }

        except Exception:
            pass

        return None

    async def _check_dehashed(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check DeHashed free search (limited)."""
        try:
            # DeHashed has a free search page
            resp = await client.get(
                f"https://dehashed.com/search?query={email}",
                headers=self.headers,
                timeout=self.timeout,
                follow_redirects=True,
            )

            if resp.status_code == 200:
                # Check if results found (basic check)
                if "entries found" in resp.text.lower():
                    # Try to extract count
                    match = re.search(r'(\d+)\s*entries?\s*found', resp.text.lower())
                    if match:
                        return {
                            "found": True,
                            "count": int(match.group(1)),
                            "source": "DeHashed",
                        }

        except Exception:
            pass

        return None

    async def _search_psbdmp(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> list[dict]:
        """Search psbdmp.ws paste archive."""
        results = []

        try:
            resp = await client.get(
                f"https://psbdmp.ws/api/v3/search/{email}",
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for paste in data[:10]:
                        results.append({
                            "id": paste.get("id", ""),
                            "tags": paste.get("tags", []),
                            "time": paste.get("time", ""),
                            "source": "psbdmp",
                        })

        except Exception:
            pass

        return results

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search paste and leak sites for email."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            total_exposures = 0
            sources_found = []

            # Search GitHub Gists/Code
            github_results = await self._search_github_gists(client, email)
            if github_results:
                total_exposures += len(github_results)
                sources_found.append("GitHub")

                for result in github_results[:5]:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.HIGH,
                        title=f"GitHub: {result['path'][:40]}",
                        description=f"Email found in {result['repo']}",
                        source="GitHub Code Search",
                        source_url=result["url"],
                        timestamp=datetime.utcnow(),
                        data={
                            "repo": result["repo"],
                            "path": result["path"],
                            "url": result["url"],
                            "remediation": "Check if credentials were exposed; rotate if necessary",
                        },
                        parent_id=parent_id,
                        link_label="found in",
                    )

            import asyncio
            await asyncio.sleep(1)

            # Search psbdmp paste archive
            psbdmp_results = await self._search_psbdmp(client, email)
            if psbdmp_results:
                total_exposures += len(psbdmp_results)
                sources_found.append("Paste Archives")

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.CRITICAL,
                    title=f"Found in {len(psbdmp_results)} Paste Dump(s)",
                    description="Email appeared in paste site archives",
                    source="Paste Archive Search",
                    timestamp=datetime.utcnow(),
                    data={
                        "paste_count": len(psbdmp_results),
                        "pastes": psbdmp_results,
                        "remediation": "Check for leaked credentials; change passwords immediately",
                    },
                    parent_id=parent_id,
                    link_label="dumped in",
                )

            await asyncio.sleep(1)

            # Check IntelX
            intelx_result = await self._search_intelx(client, email)
            if intelx_result and intelx_result.get("found"):
                total_exposures += intelx_result.get("records", 1)
                sources_found.append("IntelX")

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.HIGH,
                    title=f"IntelX: {intelx_result.get('records', 'Multiple')} Records",
                    description="Email found in intelligence database",
                    source="Intelligence X",
                    source_url="https://intelx.io",
                    timestamp=datetime.utcnow(),
                    data={
                        "records": intelx_result.get("records"),
                        "sources": intelx_result.get("sources", []),
                        "remediation": "Review exposed data; may contain leaked credentials",
                    },
                    parent_id=parent_id,
                    link_label="indexed in",
                )

            await asyncio.sleep(1)

            # Check DeHashed (free search)
            dehashed_result = await self._check_dehashed(client, email)
            if dehashed_result and dehashed_result.get("found"):
                total_exposures += dehashed_result.get("count", 1)
                sources_found.append("DeHashed")

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.CRITICAL,
                    title=f"DeHashed: {dehashed_result.get('count', 'Multiple')} Entries",
                    description="Email found in leaked database aggregator",
                    source="DeHashed",
                    source_url="https://dehashed.com",
                    timestamp=datetime.utcnow(),
                    data={
                        "count": dehashed_result.get("count"),
                        "remediation": "Credentials likely exposed; change all passwords",
                    },
                    parent_id=parent_id,
                    link_label="leaked in",
                )

            # Summary
            if total_exposures > 0:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.HIGH,
                    title=f"Paste/Leak Exposure: {total_exposures} instances",
                    description=f"Found in: {', '.join(sources_found)}",
                    source="Paste Site Analysis",
                    timestamp=datetime.utcnow(),
                    data={
                        "total_exposures": total_exposures,
                        "sources": sources_found,
                    },
                    parent_id=parent_id,
                    link_label="exposed in",
                )
