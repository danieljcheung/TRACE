"""GitHub profile and commit lookup."""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity
from config import settings


class GitHubLookup(OSINTModule):
    name = "GitHub"
    description = "Look up GitHub profile and public data"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Look up GitHub profile for username."""

        username = seed.lower().strip()
        if not username:
            return

        headers = {
            "User-Agent": "TRACE-OSINT",
            "Accept": "application/vnd.github.v3+json",
        }

        # Use token if available for higher rate limits
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

        async with httpx.AsyncClient(headers=headers) as client:
            try:
                # Get user profile
                resp = await client.get(
                    f"https://api.github.com/users/{username}",
                    timeout=10.0,
                )

                if resp.status_code != 200:
                    return

                data = resp.json()
                profile_url = data.get("html_url", f"https://github.com/{username}")

                # Main profile finding
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.ACCOUNT,
                    severity=Severity.MEDIUM,
                    title=f"GitHub: {username}",
                    description=f"{data.get('public_repos', 0)} repos, {data.get('followers', 0)} followers",
                    source="GitHub API",
                    source_url=profile_url,
                    timestamp=datetime.utcnow(),
                    data={
                        "username": username,
                        "url": profile_url,
                        "repos": data.get("public_repos", 0),
                        "followers": data.get("followers", 0),
                        "following": data.get("following", 0),
                        "created": data.get("created_at"),
                    },
                    parent_id=parent_id,
                    link_label="profile on",
                )

                # Real name (HIGH severity - PII)
                name = data.get("name")
                if name:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Real Name: {name}",
                        description="Name from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"name": name, "source": "github"},
                        parent_id=parent_id,
                        link_label="real name",
                    )

                # Location
                location = data.get("location")
                if location:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Location: {location}",
                        description="Location from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"location": location},
                        parent_id=parent_id,
                        link_label="located in",
                    )

                # Company/Employer
                company = data.get("company")
                if company:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Employer: {company}",
                        description="Company from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"company": company},
                        parent_id=parent_id,
                        link_label="works at",
                    )

                # Public email (HIGH severity)
                email = data.get("email")
                if email:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Email: {email}",
                        description="Public email on GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"email": email},
                        parent_id=parent_id,
                        link_label="email on",
                    )

                # Blog/Website
                blog = data.get("blog")
                if blog:
                    # Ensure URL has protocol
                    if not blog.startswith(('http://', 'https://')):
                        blog = f"https://{blog}"

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.LOW,
                        title="Personal Website",
                        description="Website linked on GitHub profile",
                        source="GitHub",
                        source_url=blog,
                        timestamp=datetime.utcnow(),
                        data={"url": blog},
                        parent_id=parent_id,
                        link_label="website",
                    )

                # Bio
                bio = data.get("bio")
                if bio:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.LOW,
                        title="Bio",
                        description=bio[:150] + ("..." if len(bio) > 150 else ""),
                        source="GitHub",
                        timestamp=datetime.utcnow(),
                        data={"bio": bio},
                        parent_id=parent_id,
                        link_label="bio from",
                    )

            except Exception as e:
                print(f"[GitHub] Error: {e}")
