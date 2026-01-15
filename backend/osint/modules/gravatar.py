"""Gravatar profile lookup with username extraction."""

import httpx
import hashlib
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime
from urllib.parse import urlparse

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class GravatarLookup(OSINTModule):
    name = "Gravatar"
    description = "Look up Gravatar profile information and extract usernames"

    # Platform URL patterns for username extraction
    URL_PATTERNS = {
        r"twitter\.com/([a-zA-Z0-9_]+)": "Twitter",
        r"x\.com/([a-zA-Z0-9_]+)": "Twitter",
        r"github\.com/([a-zA-Z0-9_-]+)": "GitHub",
        r"instagram\.com/([a-zA-Z0-9_.]+)": "Instagram",
        r"linkedin\.com/in/([a-zA-Z0-9_-]+)": "LinkedIn",
        r"reddit\.com/u(?:ser)?/([a-zA-Z0-9_-]+)": "Reddit",
        r"facebook\.com/([a-zA-Z0-9.]+)": "Facebook",
        r"youtube\.com/@?([a-zA-Z0-9_-]+)": "YouTube",
        r"twitch\.tv/([a-zA-Z0-9_]+)": "Twitch",
        r"mastodon\.[a-z]+/@([a-zA-Z0-9_]+)": "Mastodon",
        r"medium\.com/@([a-zA-Z0-9_]+)": "Medium",
        r"dev\.to/([a-zA-Z0-9_]+)": "DEV",
        r"hackerrank\.com/([a-zA-Z0-9_]+)": "HackerRank",
        r"codepen\.io/([a-zA-Z0-9_]+)": "CodePen",
        r"dribbble\.com/([a-zA-Z0-9_]+)": "Dribbble",
        r"behance\.net/([a-zA-Z0-9_]+)": "Behance",
    }

    def _extract_username_from_url(self, url: str) -> tuple[str, str] | None:
        """Extract username and platform from a profile URL."""
        for pattern, platform in self.URL_PATTERNS.items():
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                username = match.group(1)
                # Filter out common non-username paths
                if username.lower() not in ['about', 'help', 'settings', 'home', 'explore', 'login', 'signup']:
                    return (username, platform)
        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Look up Gravatar profile for email."""

        email = seed.lower().strip()
        email_hash = hashlib.md5(email.encode()).hexdigest()

        profile_url = f"https://gravatar.com/{email_hash}.json"
        avatar_url = f"https://gravatar.com/avatar/{email_hash}?d=404"

        async with httpx.AsyncClient() as client:
            # Check avatar exists
            has_avatar = False
            try:
                resp = await client.get(avatar_url, timeout=5.0)
                has_avatar = resp.status_code == 200
            except Exception:
                pass

            if has_avatar:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.LOW,
                    title="Profile Photo Found",
                    description="Gravatar profile photo exists",
                    source="Gravatar",
                    source_url=f"https://gravatar.com/avatar/{email_hash}",
                    timestamp=datetime.utcnow(),
                    data={"avatar_url": avatar_url},
                    parent_id=parent_id,
                    link_label="photo on",
                )

            # Try profile JSON
            try:
                resp = await client.get(profile_url, timeout=5.0)
                if resp.status_code != 200:
                    return

                data = resp.json()
                entry = data.get("entry", [{}])[0]

                # Display name
                name = entry.get("displayName")
                if name:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Name: {name}",
                        description="Real name from Gravatar profile",
                        source="Gravatar",
                        source_url=f"https://gravatar.com/{email_hash}",
                        timestamp=datetime.utcnow(),
                        data={"name": name, "source": "gravatar"},
                        parent_id=parent_id,
                        link_label="name from",
                    )

                # Location
                location = entry.get("currentLocation")
                if location:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Location: {location}",
                        description="Location from Gravatar profile",
                        source="Gravatar",
                        timestamp=datetime.utcnow(),
                        data={"location": location},
                        parent_id=parent_id,
                        link_label="located in",
                    )

                # About
                about = entry.get("aboutMe")
                if about:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.LOW,
                        title="Bio Found",
                        description=about[:100] + ("..." if len(about) > 100 else ""),
                        source="Gravatar",
                        timestamp=datetime.utcnow(),
                        data={"bio": about},
                        parent_id=parent_id,
                        link_label="bio from",
                    )

                # Linked URLs - extract usernames
                discovered_usernames = {}
                for url_entry in entry.get("urls", []):
                    url = url_entry.get("value")
                    title = url_entry.get("title", "Linked Site")
                    if url:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.LOW,
                            title=f"Link: {title}",
                            description="URL linked in Gravatar profile",
                            source="Gravatar",
                            source_url=url,
                            timestamp=datetime.utcnow(),
                            data={"url": url, "title": title},
                            parent_id=parent_id,
                            link_label="links to",
                        )

                        # Try to extract username from URL
                        extracted = self._extract_username_from_url(url)
                        if extracted:
                            username, platform = extracted
                            if username not in discovered_usernames:
                                discovered_usernames[username] = {
                                    "username": username,
                                    "platform": platform,
                                    "url": url,
                                }

                # Yield discovered usernames
                for username, info in discovered_usernames.items():
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.USERNAME,
                        severity=Severity.HIGH,
                        title=f"{info['platform']} Username: {username}",
                        description=f"Discovered via Gravatar linked account",
                        source="Gravatar Profile",
                        source_url=info["url"],
                        timestamp=datetime.utcnow(),
                        data={
                            "username": username,
                            "platform": info["platform"],
                            "discovery_method": "gravatar_linked_account",
                            "confidence": "high",
                        },
                        parent_id=parent_id,
                        link_label="discovered username",
                    )

                # Summary if multiple usernames found
                if len(discovered_usernames) > 1:
                    platforms = [info["platform"] for info in discovered_usernames.values()]
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Gravatar: {len(discovered_usernames)} Usernames",
                        description=f"Platforms: {', '.join(set(platforms))}",
                        source="Gravatar",
                        timestamp=datetime.utcnow(),
                        data={
                            "usernames": list(discovered_usernames.keys()),
                            "platforms": list(set(platforms)),
                        },
                        parent_id=parent_id,
                        link_label="usernames found",
                    )

            except Exception as e:
                print(f"[Gravatar] Error: {e}")
