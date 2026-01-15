"""
GitHub Email Search - Find GitHub usernames by searching commits with author email.
This discovers usernames even when they're completely unrelated to the email prefix.
"""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity
from config import settings


class GitHubEmailSearch(OSINTModule):
    name = "GitHub Email Search"
    description = "Discover GitHub usernames via commit email search"

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "TRACE-OSINT",
        }
        if settings.GITHUB_TOKEN:
            self.headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search GitHub commits by author email to find usernames."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient(headers=self.headers) as client:
            discovered_users = {}

            # Search commits by author email
            try:
                resp = await client.get(
                    "https://api.github.com/search/commits",
                    params={"q": f"author-email:{email}", "per_page": 30},
                    headers={**self.headers, "Accept": "application/vnd.github.cloak-preview+json"},
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])

                    for commit in items:
                        author = commit.get("author")
                        if author:
                            username = author.get("login")
                            if username and username not in discovered_users:
                                discovered_users[username] = {
                                    "username": username,
                                    "avatar_url": author.get("avatar_url"),
                                    "profile_url": author.get("html_url"),
                                    "commit_url": commit.get("html_url"),
                                    "repo": commit.get("repository", {}).get("full_name"),
                                }

                        # Also check committer (sometimes different)
                        committer = commit.get("committer")
                        if committer and committer != author:
                            username = committer.get("login")
                            if username and username not in discovered_users:
                                discovered_users[username] = {
                                    "username": username,
                                    "avatar_url": committer.get("avatar_url"),
                                    "profile_url": committer.get("html_url"),
                                    "commit_url": commit.get("html_url"),
                                    "repo": commit.get("repository", {}).get("full_name"),
                                }

            except Exception as e:
                print(f"[GitHubEmailSearch] Commit search error: {e}")

            # Also try searching users directly (email must be public)
            try:
                resp = await client.get(
                    "https://api.github.com/search/users",
                    params={"q": f"{email} in:email", "per_page": 10},
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    for user in data.get("items", []):
                        username = user.get("login")
                        if username and username not in discovered_users:
                            discovered_users[username] = {
                                "username": username,
                                "avatar_url": user.get("avatar_url"),
                                "profile_url": user.get("html_url"),
                                "source": "email_in_profile",
                            }

            except Exception as e:
                print(f"[GitHubEmailSearch] User search error: {e}")

            # Yield findings for discovered users
            for username, info in discovered_users.items():
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.USERNAME,
                    severity=Severity.HIGH,
                    title=f"GitHub Username Discovered: {username}",
                    description=f"Found via commit history search",
                    source="GitHub Commit Search",
                    source_url=info.get("profile_url", f"https://github.com/{username}"),
                    timestamp=datetime.utcnow(),
                    data={
                        "username": username,
                        "platform": "GitHub",
                        "discovery_method": "commit_email_search",
                        "confidence": "high",
                        "avatar_url": info.get("avatar_url"),
                        "sample_commit": info.get("commit_url"),
                        "sample_repo": info.get("repo"),
                    },
                    parent_id=parent_id,
                    link_label="discovered username",
                )

            # Summary if multiple users found (rare but possible)
            if len(discovered_users) > 1:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.MEDIUM,
                    title=f"Multiple GitHub Users: {len(discovered_users)}",
                    description=f"Email used by: {', '.join(discovered_users.keys())}",
                    source="GitHub Email Search",
                    timestamp=datetime.utcnow(),
                    data={
                        "usernames": list(discovered_users.keys()),
                        "note": "Email may be shared or user has multiple accounts",
                    },
                    parent_id=parent_id,
                    link_label="multiple accounts",
                )
