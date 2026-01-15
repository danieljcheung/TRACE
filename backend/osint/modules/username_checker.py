"""Check if username exists on various platforms."""

import httpx
import asyncio
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity

# (name, url_template, check_type, success_value)
# check_type: "status" = check HTTP status, "content" = check for string in response
PLATFORMS = [
    # Code platforms
    ("GitHub", "https://github.com/{}", "status", 200),
    ("GitLab", "https://gitlab.com/{}", "status", 200),
    ("Bitbucket", "https://bitbucket.org/{}/", "status", 200),
    ("Docker Hub", "https://hub.docker.com/u/{}", "status", 200),
    ("npm", "https://www.npmjs.com/~{}", "status", 200),
    ("PyPI", "https://pypi.org/user/{}/", "status", 200),
    ("Dev.to", "https://dev.to/{}", "status", 200),

    # Social media
    ("Twitter/X", "https://x.com/{}", "status", 200),
    ("Instagram", "https://www.instagram.com/{}/", "status", 200),
    ("TikTok", "https://www.tiktok.com/@{}", "status", 200),
    ("Reddit", "https://www.reddit.com/user/{}/", "status", 200),
    ("Pinterest", "https://www.pinterest.com/{}/", "status", 200),
    ("Tumblr", "https://{}.tumblr.com/", "status", 200),

    # Professional
    ("LinkedIn", "https://www.linkedin.com/in/{}/", "status", 200),
    ("Medium", "https://medium.com/@{}", "status", 200),
    ("About.me", "https://about.me/{}", "status", 200),

    # Gaming/Streaming
    ("Twitch", "https://www.twitch.tv/{}", "status", 200),
    ("Steam", "https://steamcommunity.com/id/{}", "status", 200),

    # Creative
    ("Dribbble", "https://dribbble.com/{}", "status", 200),
    ("Behance", "https://www.behance.net/{}", "status", 200),
    ("SoundCloud", "https://soundcloud.com/{}", "status", 200),
    ("Spotify", "https://open.spotify.com/user/{}", "status", 200),
    ("Vimeo", "https://vimeo.com/{}", "status", 200),
    ("Flickr", "https://www.flickr.com/people/{}/", "status", 200),

    # Other
    ("Keybase", "https://keybase.io/{}", "status", 200),
    ("Patreon", "https://www.patreon.com/{}", "status", 200),
    ("Linktree", "https://linktr.ee/{}", "status", 200),
    ("Gravatar", "https://gravatar.com/{}", "status", 200),
    ("HackerNews", "https://news.ycombinator.com/user?id={}", "content", "karma"),
]


class UsernameChecker(OSINTModule):
    name = "Username Checker"
    description = "Check username existence across 30+ platforms"

    def __init__(self):
        self.timeout = 8.0
        self.max_concurrent = 10

    async def _check_platform(
        self,
        client: httpx.AsyncClient,
        username: str,
        platform: tuple,
    ) -> tuple[str, str, bool] | None:
        """Check single platform. Returns (name, url, exists) or None on error."""
        name, url_template, check_type, success_value = platform
        url = url_template.format(username)

        try:
            response = await client.get(
                url,
                follow_redirects=True,
                timeout=self.timeout,
            )

            if check_type == "status":
                exists = response.status_code == success_value
            else:  # content
                exists = success_value.lower() in response.text.lower()

            # Extra validation: some sites return 200 but with "not found" page
            if exists and response.status_code == 200:
                not_found_indicators = [
                    "page not found",
                    "user not found",
                    "doesn't exist",
                    "does not exist",
                    "404",
                    "not found",
                ]
                text_lower = response.text.lower()
                for indicator in not_found_indicators:
                    if indicator in text_lower and len(response.text) < 50000:
                        exists = False
                        break

            return (name, url, exists)

        except Exception:
            return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Check if username exists on platforms."""

        username = seed.lower().strip()
        if not username or len(username) < 3:
            return

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(headers=headers) as client:
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def bounded_check(platform):
                async with semaphore:
                    return await self._check_platform(client, username, platform)

            # Run all checks concurrently
            tasks = [bounded_check(p) for p in PLATFORMS]
            results = await asyncio.gather(*tasks)

            # Yield findings for successful matches
            for result in results:
                if result and result[2]:  # exists = True
                    name, url, _ = result
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"{name}",
                        description=f"Account found on {name}",
                        source=name,
                        source_url=url,
                        timestamp=datetime.utcnow(),
                        data={
                            "platform": name,
                            "url": url,
                            "username": username,
                        },
                        parent_id=parent_id,
                        link_label="found on",
                    )
