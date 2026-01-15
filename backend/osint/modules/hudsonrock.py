"""
HudsonRock Cybercrime API - Search stealer logs for credentials.
Free API that searches info-stealer malware logs.
Returns usernames for various sites where credentials were stolen.
"""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime
from urllib.parse import urlparse

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class HudsonRockSearch(OSINTModule):
    name = "HudsonRock Stealer Search"
    description = "Search info-stealer malware logs for credentials"

    API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"

    def __init__(self):
        self.timeout = 20.0

    def _extract_platform_from_url(self, url: str) -> str:
        """Extract platform name from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Map common domains to platform names
            platform_map = {
                "twitter.com": "Twitter",
                "x.com": "Twitter",
                "facebook.com": "Facebook",
                "instagram.com": "Instagram",
                "linkedin.com": "LinkedIn",
                "github.com": "GitHub",
                "reddit.com": "Reddit",
                "discord.com": "Discord",
                "twitch.tv": "Twitch",
                "steam": "Steam",
                "steampowered.com": "Steam",
                "spotify.com": "Spotify",
                "netflix.com": "Netflix",
                "amazon.com": "Amazon",
                "paypal.com": "PayPal",
                "ebay.com": "eBay",
                "dropbox.com": "Dropbox",
                "google.com": "Google",
                "gmail.com": "Google",
                "microsoft.com": "Microsoft",
                "live.com": "Microsoft",
                "outlook.com": "Microsoft",
                "apple.com": "Apple",
                "icloud.com": "Apple",
            }

            for key, value in platform_map.items():
                if key in domain:
                    return value

            # Return domain without TLD
            parts = domain.split('.')
            if len(parts) >= 2:
                return parts[-2].title()

            return domain

        except Exception:
            return "Unknown"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search HudsonRock stealer logs for credentials."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    self.API_URL,
                    params={"email": email},
                    headers={"User-Agent": "TRACE-OSINT"},
                    timeout=self.timeout,
                )

                if resp.status_code == 404:
                    # No results found (good news)
                    return

                if resp.status_code != 200:
                    return

                data = resp.json()

                # Check for stealer data
                stealers = data.get("stealers", [])

                if not stealers:
                    return

                # Critical finding - user was infected with stealer malware
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.CRITICAL,
                    title=f"STEALER MALWARE: {len(stealers)} Infection(s)",
                    description="Credentials stolen by info-stealer malware",
                    source="HudsonRock Cavalier",
                    source_url="https://cavalier.hudsonrock.com",
                    timestamp=datetime.utcnow(),
                    data={
                        "infection_count": len(stealers),
                        "remediation": "URGENT: Change ALL passwords. Scan device for malware. Enable 2FA everywhere.",
                    },
                    parent_id=parent_id,
                    link_label="infected by",
                )

                discovered_usernames = {}
                compromised_sites = set()
                total_credentials = 0

                for stealer in stealers:
                    computer_name = stealer.get("computer_name", "Unknown")
                    operating_system = stealer.get("operating_system", "Unknown")
                    date_compromised = stealer.get("date_compromised", "Unknown")
                    malware_path = stealer.get("malware_path", "")

                    # Get credentials
                    credentials = stealer.get("credentials", [])
                    total_credentials += len(credentials)

                    for cred in credentials:
                        url = cred.get("url", "")
                        username = cred.get("username", "")

                        if url:
                            platform = self._extract_platform_from_url(url)
                            compromised_sites.add(platform)

                            if username and username != email:
                                if username not in discovered_usernames:
                                    discovered_usernames[username] = {
                                        "username": username,
                                        "platform": platform,
                                        "url": url,
                                    }

                    # Yield infection details
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.CRITICAL,
                        title=f"Infection: {computer_name}",
                        description=f"OS: {operating_system} | Date: {date_compromised}",
                        source="HudsonRock Cavalier",
                        timestamp=datetime.utcnow(),
                        data={
                            "computer_name": computer_name,
                            "operating_system": operating_system,
                            "date_compromised": date_compromised,
                            "malware_path": malware_path,
                            "credentials_stolen": len(credentials),
                        },
                        parent_id=parent_id,
                        link_label="infected device",
                    )

                # Yield discovered usernames
                for username, info in list(discovered_usernames.items())[:15]:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.USERNAME,
                        severity=Severity.CRITICAL,
                        title=f"Stolen Username: {username}",
                        description=f"Credentials stolen from {info['platform']}",
                        source="HudsonRock Cavalier",
                        timestamp=datetime.utcnow(),
                        data={
                            "username": username,
                            "platform": info["platform"],
                            "discovery_method": "stealer_logs",
                            "confidence": "high",
                            "compromised_url": info["url"],
                            "remediation": f"Change password for {info['platform']} immediately",
                        },
                        parent_id=parent_id,
                        link_label="stolen credentials",
                    )

                # Summary of compromised sites
                if compromised_sites:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.CRITICAL,
                        title=f"Compromised Sites: {len(compromised_sites)}",
                        description=f"Sites: {', '.join(list(compromised_sites)[:10])}",
                        source="HudsonRock Cavalier",
                        timestamp=datetime.utcnow(),
                        data={
                            "sites": list(compromised_sites),
                            "total_credentials": total_credentials,
                            "unique_usernames": len(discovered_usernames),
                            "remediation": "Change passwords on ALL listed sites",
                        },
                        parent_id=parent_id,
                        link_label="compromised on",
                    )

            except Exception as e:
                print(f"[HudsonRock] Search error: {e}")
