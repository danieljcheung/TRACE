"""
Epieos-style email OSINT - finds Google account info, registered services, etc.
Replicates techniques used by epieos.com
"""

import httpx
import uuid
import hashlib
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class EpieosLookup(OSINTModule):
    name = "Email Intelligence"
    description = "Deep email OSINT (Google account, services, social profiles)"

    def __init__(self):
        self.timeout = 15.0

    async def _check_google_account(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check if email has a Google account and extract info."""
        try:
            # Google's people API for public profiles
            # This checks if there's a Google+ legacy or Google account
            resp = await client.get(
                f"https://www.google.com/s2/photos/public/{email}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=self.timeout,
                follow_redirects=True,
            )

            result = {}

            # Check for profile photo (indicates Google account exists)
            if resp.status_code == 200 and "image" in resp.headers.get("content-type", ""):
                result["has_google_account"] = True
                result["has_profile_photo"] = True

                # Hash the photo for correlation
                photo_hash = hashlib.md5(resp.content).hexdigest()
                result["photo_hash"] = photo_hash

            # Try Google Maps contributions
            maps_resp = await client.get(
                f"https://www.google.com/maps/contrib/0?q={email}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=self.timeout,
                follow_redirects=True,
            )

            if maps_resp.status_code == 200:
                if "Local Guide" in maps_resp.text or "contributions" in maps_resp.text:
                    result["has_maps_activity"] = True

            if result:
                return result

        except Exception as e:
            print(f"[Epieos] Google check error: {e}")

        return None

    async def _check_gravatar(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> dict | None:
        """Check Gravatar for profile info."""
        try:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()

            # Check JSON profile
            resp = await client.get(
                f"https://www.gravatar.com/{email_hash}.json",
                headers={"User-Agent": "TRACE-OSINT"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                entry = data.get("entry", [{}])[0]

                return {
                    "display_name": entry.get("displayName"),
                    "name": entry.get("name", {}),
                    "location": entry.get("currentLocation"),
                    "about": entry.get("aboutMe"),
                    "urls": [u.get("value") for u in entry.get("urls", [])],
                    "accounts": [
                        {"platform": a.get("shortname"), "url": a.get("url")}
                        for a in entry.get("accounts", [])
                    ],
                    "photos": [p.get("value") for p in entry.get("photos", [])],
                    "hash": email_hash,
                }

        except Exception:
            pass

        return None

    async def _check_holehe_services(
        self,
        client: httpx.AsyncClient,
        email: str
    ) -> list[dict]:
        """Check various services for email registration (holehe-style)."""
        registered = []

        # Services to check with their recovery/signup endpoints
        services = [
            ("Twitter", self._check_twitter),
            ("Instagram", self._check_instagram),
            ("Spotify", self._check_spotify),
            ("Discord", self._check_discord),
            ("Adobe", self._check_adobe),
            ("Amazon", self._check_amazon),
            ("Apple", self._check_apple),
            ("Microsoft", self._check_microsoft),
            ("GitHub", self._check_github),
            ("Pinterest", self._check_pinterest),
        ]

        for name, check_func in services:
            try:
                result = await check_func(client, email)
                if result and result.get("exists"):
                    registered.append({
                        "service": name,
                        **result
                    })
            except Exception:
                pass

            import asyncio
            await asyncio.sleep(0.5)

        return registered

    async def _check_twitter(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.get(
                "https://api.twitter.com/i/users/email_available.json",
                params={"email": email},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("valid"):
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_instagram(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://www.instagram.com/accounts/web_create_ajax/attempt/",
                data={"email": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "X-CSRFToken": "missing",
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("errors", {}).get("email"):
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_spotify(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.get(
                "https://spclient.wg.spotify.com/signup/public/v1/account",
                params={"validate": 1, "email": email},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == 20:
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_discord(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://discord.com/api/v9/auth/register",
                json={"email": email, "username": "test", "password": "Test123456!"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            )
            if resp.status_code == 400:
                data = resp.json()
                if "email" in str(data.get("errors", {})):
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_adobe(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://auth.services.adobe.com/signin/v2/users/accounts",
                json={"username": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                    "X-IMS-CLIENTID": "adobedotcom2",
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_amazon(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://www.amazon.com/ap/signin",
                data={"email": email},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                if "password" in resp.text.lower() and "forgot" in resp.text.lower():
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_apple(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://iforgot.apple.com/password/verify/appleid",
                json={"id": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_microsoft(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://login.live.com/GetCredentialType.srf",
                json={"username": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("IfExistsResult") == 0:
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_github(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://github.com/signup_check/email",
                data={"value": email},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                if "already taken" in resp.text.lower() or resp.text.strip() == "false":
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def _check_pinterest(self, client: httpx.AsyncClient, email: str) -> dict | None:
        try:
            resp = await client.post(
                "https://www.pinterest.com/resource/EmailExistsResource/get/",
                data={"data": f'{{"options": {{"email": "{email}"}}}}'},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("resource_response", {}).get("data"):
                    return {"exists": True}
        except Exception:
            pass
        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Perform deep email intelligence gathering."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            # Check Google account
            google = await self._check_google_account(client, email)

            if google:
                if google.get("has_google_account"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title="Google Account Detected",
                        description="Email is associated with a Google account",
                        source="Google OSINT",
                        timestamp=datetime.utcnow(),
                        data={
                            "has_profile_photo": google.get("has_profile_photo", False),
                            "has_maps_activity": google.get("has_maps_activity", False),
                            "photo_hash": google.get("photo_hash"),
                        },
                        parent_id=parent_id,
                        link_label="has account",
                    )

            import asyncio
            await asyncio.sleep(1)

            # Check Gravatar
            gravatar = await self._check_gravatar(client, email)

            if gravatar:
                # Name found
                name = gravatar.get("display_name") or gravatar.get("name", {}).get("formatted")
                if name:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Name: {name}",
                        description="Name found via Gravatar profile",
                        source="Gravatar",
                        source_url=f"https://gravatar.com/{gravatar.get('hash')}",
                        timestamp=datetime.utcnow(),
                        data={
                            "name": name,
                            "source": "gravatar",
                        },
                        parent_id=parent_id,
                        link_label="named",
                    )

                # Location
                if gravatar.get("location"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Location: {gravatar['location']}",
                        description="Location from Gravatar profile",
                        source="Gravatar",
                        timestamp=datetime.utcnow(),
                        data={
                            "location": gravatar["location"],
                            "source": "gravatar",
                        },
                        parent_id=parent_id,
                        link_label="located in",
                    )

                # Linked accounts
                if gravatar.get("accounts"):
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"Linked Accounts: {len(gravatar['accounts'])}",
                        description=", ".join([a["platform"] for a in gravatar["accounts"][:5]]),
                        source="Gravatar",
                        timestamp=datetime.utcnow(),
                        data={
                            "accounts": gravatar["accounts"],
                        },
                        parent_id=parent_id,
                        link_label="linked to",
                    )

            await asyncio.sleep(1)

            # Check service registrations (holehe-style)
            services = await self._check_holehe_services(client, email)

            if services:
                service_names = [s["service"] for s in services]

                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.ACCOUNT,
                    severity=Severity.MEDIUM,
                    title=f"Registered Services: {len(services)}",
                    description=f"Found on: {', '.join(service_names)}",
                    source="Email Registration Check",
                    timestamp=datetime.utcnow(),
                    data={
                        "services": services,
                        "count": len(services),
                    },
                    parent_id=parent_id,
                    link_label="registered on",
                )

                # Individual findings for important services
                for service in services:
                    if service["service"] in ["Twitter", "Instagram", "Discord", "GitHub"]:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Account: {service['service']}",
                            description=f"Email is registered on {service['service']}",
                            source="Email Registration Check",
                            timestamp=datetime.utcnow(),
                            data={
                                "service": service["service"],
                                "registered": True,
                            },
                            parent_id=parent_id,
                            link_label="account on",
                        )
