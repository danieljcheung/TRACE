"""Gravatar profile lookup."""

import httpx
import hashlib
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class GravatarLookup(OSINTModule):
    name = "Gravatar"
    description = "Look up Gravatar profile information"

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

                # Linked URLs
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

            except Exception as e:
                print(f"[Gravatar] Error: {e}")
