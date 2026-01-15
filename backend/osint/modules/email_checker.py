"""
Email registration checker - checks if email is registered on various services.
Similar to holehe tool - uses signup/password-reset endpoints that leak registration status.
"""

import httpx
import asyncio
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class EmailChecker(OSINTModule):
    name = "Email Registration Checker"
    description = "Check if email is registered on major services"

    def __init__(self):
        self.timeout = 10.0
        self.max_concurrent = 5  # Be respectful of rate limits

    async def _check_twitter(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Twitter registration via email availability endpoint."""
        try:
            # Twitter's guest token flow
            resp = await client.post(
                "https://api.twitter.com/1.1/guest/activate.json",
                headers={"Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return None

            guest_token = resp.json().get("guest_token")
            if not guest_token:
                return None

            # Check email availability
            resp = await client.get(
                f"https://api.twitter.com/i/users/email_available.json",
                params={"email": email},
                headers={
                    "Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
                    "x-guest-token": guest_token,
                },
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                # If email is NOT available, it's registered
                if not data.get("valid", True):
                    return {"platform": "Twitter/X", "registered": True, "url": "https://twitter.com"}
        except Exception:
            pass
        return None

    async def _check_spotify(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Spotify registration."""
        try:
            resp = await client.get(
                f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", 0)
                # Status 20 = email already registered
                if status == 20:
                    return {"platform": "Spotify", "registered": True, "url": "https://spotify.com"}
        except Exception:
            pass
        return None

    async def _check_discord(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Discord registration via register endpoint."""
        try:
            resp = await client.post(
                "https://discord.com/api/v9/auth/register",
                json={
                    "email": email,
                    "username": "checkuser123456",
                    "password": "FakePass123!@#",
                    "consent": True,
                    "date_of_birth": "1990-01-01",
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                timeout=self.timeout,
            )
            # If email is taken, Discord returns specific error
            if resp.status_code == 400:
                data = resp.json()
                errors = data.get("errors", {})
                email_errors = errors.get("email", {}).get("_errors", [])
                for err in email_errors:
                    if "already" in err.get("message", "").lower():
                        return {"platform": "Discord", "registered": True, "url": "https://discord.com"}
        except Exception:
            pass
        return None

    async def _check_github_email(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check GitHub registration."""
        try:
            resp = await client.get(
                f"https://api.github.com/search/users?q={email}+in:email",
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "TRACE-OSINT",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("total_count", 0) > 0:
                    user = data["items"][0] if data.get("items") else None
                    username = user.get("login") if user else None
                    return {
                        "platform": "GitHub",
                        "registered": True,
                        "url": f"https://github.com/{username}" if username else "https://github.com",
                        "username": username,
                    }
        except Exception:
            pass
        return None

    async def _check_adobe(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Adobe registration."""
        try:
            resp = await client.post(
                "https://auth.services.adobe.com/signin/v2/users/accounts",
                json={"username": email},
                headers={
                    "Content-Type": "application/json",
                    "x-ims-clientid": "adobedotcom2",
                    "User-Agent": "Mozilla/5.0",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("accounts"):
                    return {"platform": "Adobe", "registered": True, "url": "https://adobe.com"}
        except Exception:
            pass
        return None

    async def _check_pinterest(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Pinterest registration."""
        try:
            resp = await client.post(
                "https://www.pinterest.com/resource/EmailExistsResource/get/",
                data={
                    "source_url": "/",
                    "data": f'{{"options": {{"email": "{email}"}}, "context": {{}}}}'
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("resource_response", {}).get("data", {}).get("exists"):
                    return {"platform": "Pinterest", "registered": True, "url": "https://pinterest.com"}
        except Exception:
            pass
        return None

    async def _check_wordpress(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check WordPress.com registration."""
        try:
            resp = await client.get(
                f"https://public-api.wordpress.com/rest/v1.1/users/{email}/auth-options",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return {"platform": "WordPress", "registered": True, "url": "https://wordpress.com"}
        except Exception:
            pass
        return None

    async def _check_duolingo(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Duolingo registration."""
        try:
            resp = await client.post(
                "https://www.duolingo.com/2017-06-30/users",
                params={"email": email},
                json={
                    "age": "25",
                    "email": email,
                    "fromLanguage": "en",
                    "learningLanguage": "es",
                    "password": "FakePassword123!",
                },
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 400:
                data = resp.json()
                # Check for email already exists error
                if "email" in str(data).lower() and ("exists" in str(data).lower() or "taken" in str(data).lower()):
                    return {"platform": "Duolingo", "registered": True, "url": "https://duolingo.com"}
        except Exception:
            pass
        return None

    async def _check_amazon(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Amazon registration via password reset."""
        try:
            resp = await client.get(
                "https://www.amazon.com/ap/forgotpassword",
                params={"email": email, "showRememberMe": "true"},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html",
                },
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                # If we get a password reset page (not "no account found"), email exists
                if "password" in resp.text.lower() and "no account" not in resp.text.lower():
                    return {"platform": "Amazon", "registered": True, "url": "https://amazon.com"}
        except Exception:
            pass
        return None

    async def _check_netflix(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Netflix registration."""
        try:
            resp = await client.post(
                "https://www.netflix.com/api/shakti/vxbvj/pathEvaluator",
                params={"email": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
            # Netflix is tricky - may need cookies/session
            # Simplified check
        except Exception:
            pass
        return None

    async def _check_instagram(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Instagram registration."""
        try:
            resp = await client.post(
                "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
                data={
                    "email": email,
                    "username": "",
                    "first_name": "",
                    "opt_into_one_tap": "false",
                },
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                # email_is_taken indicates registration
                if data.get("email_is_taken"):
                    return {"platform": "Instagram", "registered": True, "url": "https://instagram.com"}
        except Exception:
            pass
        return None

    async def _check_snapchat(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check Snapchat registration."""
        try:
            resp = await client.post(
                "https://accounts.snapchat.com/accounts/merlin/check_email",
                data={"email": email},
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("account_exists"):
                    return {"platform": "Snapchat", "registered": True, "url": "https://snapchat.com"}
        except Exception:
            pass
        return None

    async def _check_ebay(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check eBay registration."""
        try:
            resp = await client.get(
                f"https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&ru=&UsingSSL=1",
                params={"userid": email},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=self.timeout,
                follow_redirects=True,
            )
            if resp.status_code == 200 and "account" in resp.text.lower():
                return {"platform": "eBay", "registered": True, "url": "https://ebay.com"}
        except Exception:
            pass
        return None

    async def _check_linkedin(self, client: httpx.AsyncClient, email: str) -> dict | None:
        """Check LinkedIn registration."""
        try:
            resp = await client.get(
                "https://www.linkedin.com/uas/login-submit",
                params={"email": email},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                timeout=self.timeout,
                follow_redirects=True,
            )
            # LinkedIn detection is tricky, simplified
        except Exception:
            pass
        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Check email registration across services."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        checks = [
            ("Twitter/X", self._check_twitter),
            ("Spotify", self._check_spotify),
            ("Discord", self._check_discord),
            ("GitHub", self._check_github_email),
            ("Adobe", self._check_adobe),
            ("Pinterest", self._check_pinterest),
            ("WordPress", self._check_wordpress),
            ("Duolingo", self._check_duolingo),
            ("Instagram", self._check_instagram),
            ("Snapchat", self._check_snapchat),
        ]

        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def bounded_check(name: str, check_func):
                async with semaphore:
                    await asyncio.sleep(0.5)  # Rate limiting
                    try:
                        return await check_func(client, email)
                    except Exception as e:
                        print(f"[EmailChecker] {name} error: {e}")
                        return None

            tasks = [bounded_check(name, func) for name, func in checks]
            results = await asyncio.gather(*tasks)

            registered_services = []
            for result in results:
                if result and result.get("registered"):
                    registered_services.append(result)

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"Registered: {result['platform']}",
                        description=f"Email is registered on {result['platform']}",
                        source="Email Registration Check",
                        source_url=result.get("url"),
                        timestamp=datetime.utcnow(),
                        data={
                            "platform": result["platform"],
                            "email": email,
                            "username": result.get("username"),
                            "registration_confirmed": True,
                        },
                        parent_id=parent_id,
                        link_label="registered on",
                    )

            # Summary finding
            if registered_services:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.HIGH if len(registered_services) > 5 else Severity.MEDIUM,
                    title=f"Email Active on {len(registered_services)} Services",
                    description=f"Found registrations: {', '.join(r['platform'] for r in registered_services)}",
                    source="Email Registration Analysis",
                    timestamp=datetime.utcnow(),
                    data={
                        "services": [r["platform"] for r in registered_services],
                        "count": len(registered_services),
                    },
                    parent_id=parent_id,
                    link_label="activity summary",
                )
