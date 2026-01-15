"""
Wayback Machine lookup - searches Archive.org for historical data.
"""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class WaybackLookup(OSINTModule):
    name = "Archive.org Lookup"
    description = "Search Wayback Machine for historical profile data"

    CDX_API = "https://web.archive.org/cdx/search/cdx"
    WAYBACK_URL = "https://web.archive.org/web"

    def __init__(self):
        self.timeout = 20.0

    async def _search_cdx(
        self,
        client: httpx.AsyncClient,
        url: str,
        limit: int = 10
    ) -> list[dict]:
        """Search Wayback CDX API for archived versions."""
        results = []

        try:
            resp = await client.get(
                self.CDX_API,
                params={
                    "url": url,
                    "output": "json",
                    "limit": limit,
                    "fl": "timestamp,original,statuscode,mimetype",
                },
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()

                # First row is headers
                if data and len(data) > 1:
                    for row in data[1:]:
                        if len(row) >= 4:
                            timestamp, original, status, mimetype = row[:4]
                            if status == "200":
                                results.append({
                                    "timestamp": timestamp,
                                    "url": original,
                                    "archive_url": f"{self.WAYBACK_URL}/{timestamp}/{original}",
                                    "mimetype": mimetype,
                                    "date": self._parse_timestamp(timestamp),
                                })

        except Exception as e:
            print(f"[Wayback] CDX error: {e}")

        return results

    def _parse_timestamp(self, ts: str) -> str:
        """Convert Wayback timestamp to readable date."""
        try:
            if len(ts) >= 8:
                return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        except Exception:
            pass
        return ts

    async def _search_email_mentions(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> list[dict]:
        """Search for archived pages containing the email."""
        results = []

        # Search patterns
        search_patterns = [
            f"*{email}*",
            email,
        ]

        for pattern in search_patterns:
            try:
                resp = await client.get(
                    self.CDX_API,
                    params={
                        "url": pattern,
                        "output": "json",
                        "limit": 20,
                        "matchType": "domain" if "*" not in pattern else "prefix",
                        "fl": "timestamp,original,statuscode",
                    },
                    headers={"User-Agent": "TRACE-OSINT"},
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    if data and len(data) > 1:
                        for row in data[1:10]:
                            if len(row) >= 3 and row[2] == "200":
                                results.append({
                                    "timestamp": row[0],
                                    "url": row[1],
                                    "archive_url": f"{self.WAYBACK_URL}/{row[0]}/{row[1]}",
                                    "date": self._parse_timestamp(row[0]),
                                })

            except Exception:
                continue

        return results

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search Wayback Machine for historical data."""

        # Seed can be email or URL
        seed = seed.strip()

        async with httpx.AsyncClient() as client:
            # If it looks like a URL, search directly
            if seed.startswith("http") or "." in seed and "@" not in seed:
                archives = await self._search_cdx(client, seed)

                if archives:
                    oldest = min(archives, key=lambda x: x["timestamp"])
                    newest = max(archives, key=lambda x: x["timestamp"])

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Archived: {len(archives)} snapshots",
                        description=f"Historical versions from {oldest['date']} to {newest['date']}",
                        source="Wayback Machine",
                        source_url=archives[0]["archive_url"],
                        timestamp=datetime.utcnow(),
                        data={
                            "snapshot_count": len(archives),
                            "oldest": oldest,
                            "newest": newest,
                            "all_snapshots": archives[:10],
                            "remediation": "Historical data cannot be removed from Archive.org",
                        },
                        parent_id=parent_id,
                        link_label="archived at",
                    )

            # If it's an email, search for common profile URLs
            elif "@" in seed:
                email = seed.lower()
                username = email.split("@")[0]
                domain = email.split("@")[1]

                # URLs to check
                profile_urls = [
                    f"https://twitter.com/{username}",
                    f"https://github.com/{username}",
                    f"https://instagram.com/{username}",
                    f"https://linkedin.com/in/{username}",
                    f"https://facebook.com/{username}",
                    f"https://{username}.tumblr.com",
                    f"https://about.me/{username}",
                    f"https://{username}.wordpress.com",
                    f"https://{username}.blogspot.com",
                ]

                # If custom domain, check personal site
                if domain not in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]:
                    profile_urls.insert(0, f"https://{domain}")
                    profile_urls.insert(1, f"https://www.{domain}")

                found_archives = []

                for url in profile_urls[:8]:  # Limit to avoid rate limits
                    archives = await self._search_cdx(client, url, limit=5)

                    if archives:
                        found_archives.append({
                            "url": url,
                            "snapshots": len(archives),
                            "oldest": min(archives, key=lambda x: x["timestamp"]),
                            "archive_url": archives[0]["archive_url"],
                        })

                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Archived Profile: {url.split('//')[1].split('/')[0]}",
                            description=f"{len(archives)} snapshots found",
                            source="Wayback Machine",
                            source_url=archives[0]["archive_url"],
                            timestamp=datetime.utcnow(),
                            data={
                                "url": url,
                                "snapshots": len(archives),
                                "oldest_date": archives[-1]["date"] if archives else None,
                                "newest_date": archives[0]["date"] if archives else None,
                                "remediation": "Review archived content for exposed personal info",
                            },
                            parent_id=parent_id,
                            link_label="archived at",
                        )

                    import asyncio
                    await asyncio.sleep(0.5)

                # Summary if multiple archives found
                if len(found_archives) > 1:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Archive History: {len(found_archives)} profiles",
                        description="Historical versions of user profiles found",
                        source="Wayback Machine",
                        source_url="https://web.archive.org",
                        timestamp=datetime.utcnow(),
                        data={
                            "profiles_archived": len(found_archives),
                            "archives": found_archives,
                            "note": "May contain old personal info, deleted posts, etc.",
                        },
                        parent_id=parent_id,
                        link_label="history on",
                    )
