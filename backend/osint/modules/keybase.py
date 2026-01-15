"""
Keybase Lookup - Find verified linked accounts via Keybase proofs.
Keybase users prove ownership of accounts on Twitter, GitHub, Reddit, etc.
These are cryptographically verified, not guesses.
"""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class KeybaseLookup(OSINTModule):
    name = "Keybase Lookup"
    description = "Find verified linked accounts via Keybase"

    API_URL = "https://keybase.io/_/api/1.0/user/lookup.json"

    def __init__(self):
        self.timeout = 15.0

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Lookup email on Keybase to find verified account links."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            try:
                # Try email lookup
                resp = await client.get(
                    self.API_URL,
                    params={"email": email},
                    headers={"User-Agent": "TRACE-OSINT"},
                    timeout=self.timeout,
                )

                if resp.status_code != 200:
                    return

                data = resp.json()

                # Check if lookup was successful
                if data.get("status", {}).get("code") != 0:
                    return

                them = data.get("them")
                if not them:
                    return

                # Handle both single user and list
                users = them if isinstance(them, list) else [them]

                for user in users:
                    if not user:
                        continue

                    basics = user.get("basics", {})
                    keybase_username = basics.get("username")

                    if not keybase_username:
                        continue

                    # Main Keybase profile finding
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.USERNAME,
                        severity=Severity.HIGH,
                        title=f"Keybase Username: {keybase_username}",
                        description="Verified Keybase identity found",
                        source="Keybase",
                        source_url=f"https://keybase.io/{keybase_username}",
                        timestamp=datetime.utcnow(),
                        data={
                            "username": keybase_username,
                            "platform": "Keybase",
                            "discovery_method": "keybase_email_lookup",
                            "confidence": "verified",
                        },
                        parent_id=parent_id,
                        link_label="keybase identity",
                    )

                    # Extract verified proofs (linked accounts)
                    proofs = user.get("proofs_summary", {}).get("all", [])

                    verified_accounts = []
                    for proof in proofs:
                        proof_type = proof.get("proof_type")
                        nametag = proof.get("nametag")
                        service_url = proof.get("service_url")
                        state = proof.get("state")

                        # Only include verified proofs (state == 1)
                        if state == 1 and nametag:
                            platform_map = {
                                "twitter": "Twitter",
                                "github": "GitHub",
                                "reddit": "Reddit",
                                "hackernews": "HackerNews",
                                "facebook": "Facebook",
                                "generic_web_site": "Website",
                                "dns": "Domain",
                                "mastodon": "Mastodon",
                            }

                            platform = platform_map.get(proof_type, proof_type)

                            verified_accounts.append({
                                "platform": platform,
                                "username": nametag,
                                "url": service_url,
                                "verified": True,
                            })

                            # Yield individual username discoveries for important platforms
                            if platform in ["Twitter", "GitHub", "Reddit", "HackerNews"]:
                                yield Finding(
                                    id=str(uuid.uuid4()),
                                    type=NodeType.USERNAME,
                                    severity=Severity.HIGH,
                                    title=f"{platform} Username: {nametag}",
                                    description=f"Cryptographically verified via Keybase",
                                    source="Keybase Proof",
                                    source_url=service_url or f"https://keybase.io/{keybase_username}",
                                    timestamp=datetime.utcnow(),
                                    data={
                                        "username": nametag,
                                        "platform": platform,
                                        "discovery_method": "keybase_proof",
                                        "confidence": "verified",
                                        "keybase_username": keybase_username,
                                    },
                                    parent_id=parent_id,
                                    link_label="verified account",
                                )

                    # Summary of all verified accounts
                    if verified_accounts:
                        platforms = [a["platform"] for a in verified_accounts]
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Keybase Verified Accounts: {len(verified_accounts)}",
                            description=f"Verified on: {', '.join(set(platforms))}",
                            source="Keybase",
                            source_url=f"https://keybase.io/{keybase_username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "accounts": verified_accounts,
                                "keybase_username": keybase_username,
                                "note": "All accounts cryptographically verified",
                            },
                            parent_id=parent_id,
                            link_label="verified links",
                        )

                    # Check for PGP keys
                    public_keys = user.get("public_keys", {})
                    pgp_keys = public_keys.get("pgp_public_keys", [])

                    if pgp_keys:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"PGP Keys: {len(pgp_keys)} found",
                            description="PGP public keys on Keybase",
                            source="Keybase",
                            source_url=f"https://keybase.io/{keybase_username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "key_count": len(pgp_keys),
                                "keybase_username": keybase_username,
                            },
                            parent_id=parent_id,
                            link_label="pgp keys",
                        )

                    # Check profile info
                    profile = user.get("profile", {})
                    full_name = profile.get("full_name")
                    location = profile.get("location")
                    bio = profile.get("bio")

                    if full_name:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.HIGH,
                            title=f"Name: {full_name}",
                            description="Name from Keybase profile",
                            source="Keybase",
                            source_url=f"https://keybase.io/{keybase_username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "name": full_name,
                                "source": "keybase_profile",
                                "confidence": "high",
                            },
                            parent_id=parent_id,
                            link_label="name",
                        )

                    if location:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location: {location}",
                            description="Location from Keybase profile",
                            source="Keybase",
                            timestamp=datetime.utcnow(),
                            data={
                                "location": location,
                                "source": "keybase_profile",
                            },
                            parent_id=parent_id,
                            link_label="located in",
                        )

            except Exception as e:
                print(f"[Keybase] Lookup error: {e}")
