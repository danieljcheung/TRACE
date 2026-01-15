"""
Check if username exists on various platforms.
Uses APIs where available to reduce false positives.
"""

import httpx
import asyncio
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity
from config import settings


class UsernameChecker(OSINTModule):
    name = "Username Checker"
    description = "Check username existence across platforms (API-validated)"

    def __init__(self):
        self.timeout = 10.0
        self.max_concurrent = 8

    async def _check_github(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """GitHub API check - most reliable."""
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if settings.GITHUB_TOKEN:
                headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

            resp = await client.get(
                f"https://api.github.com/users/{username}",
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "platform": "GitHub",
                    "url": f"https://github.com/{username}",
                    "verified": True,
                    "extra": {
                        "name": data.get("name"),
                        "repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                    }
                }
        except Exception:
            pass
        return None

    async def _check_reddit(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Reddit API check."""
        try:
            resp = await client.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "TRACE-OSINT/1.0"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and data["data"].get("name"):
                    return {
                        "platform": "Reddit",
                        "url": f"https://reddit.com/u/{username}",
                        "verified": True,
                        "extra": {
                            "karma": data["data"].get("total_karma"),
                            "created": data["data"].get("created_utc"),
                        }
                    }
        except Exception:
            pass
        return None

    async def _check_gitlab(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """GitLab API check."""
        try:
            resp = await client.get(
                f"https://gitlab.com/api/v4/users?username={username}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data and len(data) > 0:
                    user = data[0]
                    return {
                        "platform": "GitLab",
                        "url": f"https://gitlab.com/{username}",
                        "verified": True,
                        "extra": {
                            "name": user.get("name"),
                            "avatar": user.get("avatar_url"),
                        }
                    }
        except Exception:
            pass
        return None

    async def _check_keybase(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Keybase API check."""
        try:
            resp = await client.get(
                f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status", {}).get("code") == 0 and data.get("them"):
                    return {
                        "platform": "Keybase",
                        "url": f"https://keybase.io/{username}",
                        "verified": True,
                        "extra": {
                            "proofs": len(data.get("them", {}).get("proofs_summary", {}).get("all", [])),
                        }
                    }
        except Exception:
            pass
        return None

    async def _check_hackernews(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """HackerNews check with content validation."""
        try:
            resp = await client.get(
                f"https://news.ycombinator.com/user?id={username}",
                timeout=self.timeout,
            )
            if resp.status_code == 200 and "karma:" in resp.text.lower():
                # Extract karma
                karma_match = re.search(r'karma:\s*(\d+)', resp.text, re.IGNORECASE)
                karma = int(karma_match.group(1)) if karma_match else 0
                return {
                    "platform": "HackerNews",
                    "url": f"https://news.ycombinator.com/user?id={username}",
                    "verified": True,
                    "extra": {"karma": karma}
                }
        except Exception:
            pass
        return None

    async def _check_twitch(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Twitch check with content validation."""
        try:
            resp = await client.get(
                f"https://www.twitch.tv/{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                # Twitch shows specific content for existing users
                text = resp.text.lower()
                # Check for valid profile indicators
                if '"@type":"person"' in text.lower() or f'"{username}"' in text.lower():
                    # Make sure it's not an error page
                    if "sorry. unless you've got a time machine" not in text:
                        return {
                            "platform": "Twitch",
                            "url": f"https://twitch.tv/{username}",
                            "verified": True,
                        }
        except Exception:
            pass
        return None

    async def _check_steam(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Steam custom URL check with content validation."""
        try:
            resp = await client.get(
                f"https://steamcommunity.com/id/{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                text = resp.text
                # Valid profile has these indicators
                if "profile_header" in text and "persona_name" in text:
                    return {
                        "platform": "Steam",
                        "url": f"https://steamcommunity.com/id/{username}",
                        "verified": True,
                    }
        except Exception:
            pass
        return None

    async def _check_medium(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Medium check with content validation."""
        try:
            resp = await client.get(
                f"https://medium.com/@{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                text = resp.text.lower()
                # Valid Medium profile has specific meta tags
                if 'property="profile:username"' in text or f'"@{username}"' in text.lower():
                    return {
                        "platform": "Medium",
                        "url": f"https://medium.com/@{username}",
                        "verified": True,
                    }
        except Exception:
            pass
        return None

    async def _check_devto(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Dev.to API check."""
        try:
            resp = await client.get(
                f"https://dev.to/api/users/by_username?url={username}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("username"):
                    return {
                        "platform": "Dev.to",
                        "url": f"https://dev.to/{username}",
                        "verified": True,
                        "extra": {
                            "name": data.get("name"),
                            "joined": data.get("joined_at"),
                        }
                    }
        except Exception:
            pass
        return None

    async def _check_npm(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """npm registry check."""
        try:
            resp = await client.get(
                f"https://registry.npmjs.org/-/user/org.couchdb.user:{username}",
                timeout=self.timeout,
            )
            # npm returns 404 for non-existent users, 200 for existing
            if resp.status_code == 200:
                return {
                    "platform": "npm",
                    "url": f"https://www.npmjs.com/~{username}",
                    "verified": True,
                }
        except Exception:
            pass
        return None

    async def _check_pypi(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """PyPI user check with content validation."""
        try:
            resp = await client.get(
                f"https://pypi.org/user/{username}/",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                # Check for valid profile content
                if "Projects maintained" in resp.text or "packages maintained" in resp.text.lower():
                    return {
                        "platform": "PyPI",
                        "url": f"https://pypi.org/user/{username}/",
                        "verified": True,
                    }
        except Exception:
            pass
        return None

    async def _check_dockerhub(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Docker Hub API check."""
        try:
            resp = await client.get(
                f"https://hub.docker.com/v2/users/{username}/",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("username"):
                    return {
                        "platform": "Docker Hub",
                        "url": f"https://hub.docker.com/u/{username}",
                        "verified": True,
                        "extra": {
                            "date_joined": data.get("date_joined"),
                        }
                    }
        except Exception:
            pass
        return None

    async def _check_linktree(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Linktree check with content validation."""
        try:
            resp = await client.get(
                f"https://linktr.ee/{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                # Valid linktree has specific content
                if "linktree" in resp.text.lower() and "the link you followed may be broken" not in resp.text.lower():
                    # Check for actual profile content
                    if '"links"' in resp.text or 'data-testid="ProfileHeader"' in resp.text:
                        return {
                            "platform": "Linktree",
                            "url": f"https://linktr.ee/{username}",
                            "verified": True,
                        }
        except Exception:
            pass
        return None

    async def _check_soundcloud(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """SoundCloud check with content validation."""
        try:
            resp = await client.get(
                f"https://soundcloud.com/{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                text = resp.text
                # Valid profile indicators
                if '"@type":"Person"' in text or 'property="soundcloud:user"' in text:
                    return {
                        "platform": "SoundCloud",
                        "url": f"https://soundcloud.com/{username}",
                        "verified": True,
                    }
        except Exception:
            pass
        return None

    async def _check_about_me(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """About.me check with content validation."""
        try:
            resp = await client.get(
                f"https://about.me/{username}",
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                # Valid profile has specific meta content
                if 'property="og:type" content="profile"' in resp.text:
                    return {
                        "platform": "About.me",
                        "url": f"https://about.me/{username}",
                        "verified": True,
                    }
        except Exception:
            pass
        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Check if username exists on platforms using APIs and content validation."""

        username = seed.strip()
        if not username or len(username) < 2:
            return

        # Skip usernames that are too common or likely invalid
        common_invalid = ['admin', 'test', 'user', 'root', 'null', 'undefined']
        if username.lower() in common_invalid:
            return

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(headers=headers) as client:
            # Run all API checks concurrently
            checks = [
                self._check_github(client, username),
                self._check_reddit(client, username),
                self._check_gitlab(client, username),
                self._check_keybase(client, username),
                self._check_hackernews(client, username),
                self._check_twitch(client, username),
                self._check_steam(client, username),
                self._check_medium(client, username),
                self._check_devto(client, username),
                self._check_npm(client, username),
                self._check_pypi(client, username),
                self._check_dockerhub(client, username),
                self._check_linktree(client, username),
                self._check_soundcloud(client, username),
                self._check_about_me(client, username),
            ]

            results = await asyncio.gather(*checks)

            found_count = 0
            for result in results:
                if result:
                    found_count += 1
                    platform = result["platform"]
                    url = result["url"]
                    extra = result.get("extra", {})

                    # Build description with extra info if available
                    desc_parts = [f"Verified account on {platform}"]
                    if extra.get("name"):
                        desc_parts.append(f"Name: {extra['name']}")
                    if extra.get("repos"):
                        desc_parts.append(f"{extra['repos']} repos")
                    if extra.get("karma"):
                        desc_parts.append(f"{extra['karma']} karma")

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"{platform}: {username}",
                        description=desc_parts[0],
                        source=f"{platform} (API verified)",
                        source_url=url,
                        timestamp=datetime.utcnow(),
                        data={
                            "platform": platform,
                            "url": url,
                            "username": username,
                            "verified": True,
                            **extra,
                        },
                        parent_id=parent_id,
                        link_label="found on",
                    )

            # Summary finding if we found accounts
            if found_count > 0:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.LOW,
                    title=f"Username '{username}' found on {found_count} platforms",
                    description="Username correlation across multiple services",
                    source="Username Analysis",
                    timestamp=datetime.utcnow(),
                    data={
                        "username": username,
                        "platforms_found": found_count,
                    },
                    parent_id=parent_id,
                    link_label="appears on",
                )
