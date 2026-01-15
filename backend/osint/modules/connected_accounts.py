"""
Connected account finder - discovers cross-platform links and same-identity accounts.
"""

import httpx
import uuid
import re
import hashlib
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class ConnectedAccountFinder(OSINTModule):
    name = "Connected Account Finder"
    description = "Find linked accounts across platforms"

    def __init__(self):
        self.timeout = 10.0

    def _extract_social_links(self, text: str) -> list[dict]:
        """Extract social media links/handles from text."""
        links = []

        # Twitter/X patterns
        twitter_patterns = [
            r'twitter\.com/(\w+)',
            r'x\.com/(\w+)',
            r'@(\w+)(?:\s+on\s+twitter|\s+on\s+x)?',
            r'twitter:\s*@?(\w+)',
        ]
        for pattern in twitter_patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches:
                if len(match) >= 3 and match not in ['twitter', 'com', 'the', 'and']:
                    links.append({"platform": "Twitter", "username": match})

        # Instagram patterns
        ig_patterns = [
            r'instagram\.com/(\w+)',
            r'instagram:\s*@?(\w+)',
            r'ig:\s*@?(\w+)',
        ]
        for pattern in ig_patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches:
                if len(match) >= 3:
                    links.append({"platform": "Instagram", "username": match})

        # LinkedIn patterns
        li_patterns = [
            r'linkedin\.com/in/([a-z0-9-]+)',
            r'linkedin:\s*([a-z0-9-]+)',
        ]
        for pattern in li_patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches:
                links.append({"platform": "LinkedIn", "username": match})

        # GitHub patterns
        gh_patterns = [
            r'github\.com/(\w+)',
            r'github:\s*@?(\w+)',
        ]
        for pattern in gh_patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches:
                if len(match) >= 2:
                    links.append({"platform": "GitHub", "username": match})

        # YouTube patterns
        yt_patterns = [
            r'youtube\.com/(?:c/|channel/|user/|@)(\w+)',
        ]
        for pattern in yt_patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches:
                links.append({"platform": "YouTube", "username": match})

        # Generic URL extraction
        url_pattern = r'https?://([a-zA-Z0-9.-]+)/([a-zA-Z0-9_-]+)'
        url_matches = re.findall(url_pattern, text)
        for domain, path in url_matches:
            if any(social in domain for social in ['facebook', 'tiktok', 'twitch', 'reddit']):
                platform = domain.split('.')[0].title()
                if len(path) >= 2:
                    links.append({"platform": platform, "username": path})

        return links

    def _hash_avatar(self, avatar_data: bytes) -> str:
        """Generate hash of avatar image for comparison."""
        return hashlib.md5(avatar_data).hexdigest()

    async def _check_username_availability(
        self,
        client: httpx.AsyncClient,
        username: str,
        platforms: list[str]
    ) -> list[dict]:
        """Check if username exists on platforms (quick API checks)."""
        found = []

        platform_apis = {
            "GitHub": f"https://api.github.com/users/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}/about.json",
            "GitLab": f"https://gitlab.com/api/v4/users?username={username}",
            "Keybase": f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
        }

        for platform in platforms:
            if platform not in platform_apis:
                continue

            try:
                resp = await client.get(
                    platform_apis[platform],
                    headers={"User-Agent": "TRACE-OSINT"},
                    timeout=5.0,
                )

                exists = False
                if platform == "GitHub" and resp.status_code == 200:
                    exists = True
                elif platform == "Reddit" and resp.status_code == 200:
                    data = resp.json()
                    exists = "data" in data and data["data"].get("name")
                elif platform == "GitLab" and resp.status_code == 200:
                    data = resp.json()
                    exists = len(data) > 0
                elif platform == "Keybase" and resp.status_code == 200:
                    data = resp.json()
                    exists = data.get("status", {}).get("code") == 0

                if exists:
                    found.append({
                        "platform": platform,
                        "username": username,
                        "url": platform_apis[platform].replace("/api/", "/").replace(".json", ""),
                    })

            except Exception:
                pass

        return found

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Find connected accounts.

        Seed format: JSON with accounts found so far.
        Example: {"usernames": ["john_doe"], "bios": ["Follow me @johnd on twitter"], "avatars": {...}}
        """
        import json

        try:
            data = json.loads(seed) if isinstance(seed, str) else seed
        except (json.JSONDecodeError, TypeError):
            return

        usernames = data.get("usernames", [])
        bios = data.get("bios", [])
        found_accounts = data.get("found_accounts", [])  # Already found platforms

        async with httpx.AsyncClient(follow_redirects=True) as client:

            # Extract links from bios
            all_links = []
            for bio in bios:
                if bio:
                    extracted = self._extract_social_links(bio)
                    all_links.extend(extracted)

            # Dedupe
            seen = set()
            unique_links = []
            for link in all_links:
                key = f"{link['platform']}:{link['username']}"
                if key not in seen:
                    seen.add(key)
                    unique_links.append(link)

            # Report linked accounts from bios
            for link in unique_links:
                # Skip if we already found this account
                if any(
                    a.get("platform", "").lower() == link["platform"].lower() and
                    a.get("username", "").lower() == link["username"].lower()
                    for a in found_accounts
                ):
                    continue

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.ACCOUNT,
                    severity=Severity.MEDIUM,
                    title=f"Linked: {link['platform']} @{link['username']}",
                    description=f"Account mentioned in profile bio",
                    source="Bio Analysis",
                    source_url=self._get_profile_url(link["platform"], link["username"]),
                    timestamp=datetime.utcnow(),
                    data={
                        "platform": link["platform"],
                        "username": link["username"],
                        "discovery_method": "bio_mention",
                    },
                    parent_id=parent_id,
                    link_label="links to",
                )

            # Check same username on other platforms
            platforms_to_check = ["GitHub", "Reddit", "GitLab", "Keybase"]
            found_platforms = [a.get("platform", "").lower() for a in found_accounts]

            for username in usernames[:3]:  # Limit to avoid rate limits
                # Remove platforms we already found
                remaining = [p for p in platforms_to_check if p.lower() not in found_platforms]

                if remaining:
                    matches = await self._check_username_availability(client, username, remaining)

                    for match in matches:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Same Username: {match['platform']}",
                            description=f"Username '{username}' also exists on {match['platform']}",
                            source="Username Correlation",
                            source_url=self._get_profile_url(match["platform"], username),
                            timestamp=datetime.utcnow(),
                            data={
                                "platform": match["platform"],
                                "username": username,
                                "discovery_method": "username_match",
                                "confidence": "high",
                            },
                            parent_id=parent_id,
                            link_label="same user on",
                        )

            # Summary if we found connections
            total_connections = len(unique_links) + sum(1 for _ in [])  # Placeholder for additional
            if total_connections > 0:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.LOW,
                    title=f"Account Network: {total_connections} connections",
                    description="Cross-platform account relationships identified",
                    source="Connection Analysis",
                    timestamp=datetime.utcnow(),
                    data={
                        "total_connections": total_connections,
                        "linked_accounts": unique_links,
                    },
                    parent_id=parent_id,
                    link_label="connected to",
                )

    def _get_profile_url(self, platform: str, username: str) -> str:
        """Get profile URL for a platform."""
        urls = {
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://reddit.com/u/{username}",
            "GitLab": f"https://gitlab.com/{username}",
            "Keybase": f"https://keybase.io/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Facebook": f"https://facebook.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
        }
        return urls.get(platform, f"https://{platform.lower()}.com/{username}")
