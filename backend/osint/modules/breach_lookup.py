"""
Check for data breaches using XposedOrNot API.
Free API, no key required, 1 req/sec rate limit.
Docs: https://xposedornot.com/api_doc
"""

import httpx
import uuid
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class BreachLookup(OSINTModule):
    name = "Breach Lookup"
    description = "Check for data breaches via XposedOrNot"

    API_URL = "https://api.xposedornot.com/v1/breach-analytics"

    def __init__(self):
        self.timeout = 15.0

    def _determine_severity(self, data_exposed: list[str], password_risk: str | None) -> Severity:
        """Determine severity based on exposed data types."""
        data_lower = [d.lower() for d in data_exposed]

        # CRITICAL: plaintext passwords, SSN, financial
        critical_indicators = [
            "plaintext" in (password_risk or "").lower(),
            any(term in " ".join(data_lower) for term in [
                "ssn", "social security", "credit card", "bank account",
                "financial", "tax", "passport"
            ])
        ]
        if any(critical_indicators):
            return Severity.CRITICAL

        # HIGH: any passwords, or phone+address combo
        has_password = any("password" in d for d in data_lower) or password_risk
        has_phone = any("phone" in d for d in data_lower)
        has_address = any("address" in d for d in data_lower)

        if has_password or (has_phone and has_address):
            return Severity.HIGH

        # MEDIUM: phone, address, or DOB alone
        medium_indicators = ["phone", "address", "dob", "date of birth", "birthday", "ip address"]
        if any(term in " ".join(data_lower) for term in medium_indicators):
            return Severity.MEDIUM

        # LOW: just email/username
        return Severity.LOW

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Check email for data breaches via XposedOrNot."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    self.API_URL,
                    params={"email": email},
                    headers={"User-Agent": "TRACE-OSINT/1.0"},
                    timeout=self.timeout,
                )

                # Handle 404 - no breaches found
                if resp.status_code == 404:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.LOW,
                        title="No Breaches Found",
                        description="Email not found in any known data breaches",
                        source="XposedOrNot",
                        source_url="https://xposedornot.com",
                        timestamp=datetime.utcnow(),
                        data={"status": "clean", "breaches_found": 0},
                        parent_id=parent_id,
                        link_label="checked against",
                    )
                    return

                # Handle rate limiting
                if resp.status_code == 429:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.LOW,
                        title="Breach Check Rate Limited",
                        description="Too many requests, try again later",
                        source="XposedOrNot",
                        timestamp=datetime.utcnow(),
                        data={"status": "rate_limited"},
                        parent_id=parent_id,
                        link_label="rate limited",
                    )
                    return

                if resp.status_code != 200:
                    return

                data = resp.json()

                # Extract breach data
                exposed_breaches = data.get("ExposedBreaches", {})
                breaches_details = exposed_breaches.get("breaches_details", [])
                metrics = data.get("BreachMetrics", {})
                pastes = data.get("PastesSummary", {})

                # Get summary metrics
                risk_score = metrics.get("risk_score", 0) if metrics else 0
                risk_label = metrics.get("risk_label", "Unknown") if metrics else "Unknown"
                breach_count = len(breaches_details)

                # Summary finding
                if breach_count > 0:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.CRITICAL if risk_score >= 7 else Severity.HIGH if risk_score >= 4 else Severity.MEDIUM,
                        title=f"Found in {breach_count} Data Breach(es)",
                        description=f"Risk Level: {risk_label} ({risk_score}/10)",
                        source="XposedOrNot",
                        source_url=f"https://xposedornot.com/xposed/{email}",
                        timestamp=datetime.utcnow(),
                        data={
                            "breach_count": breach_count,
                            "risk_score": risk_score,
                            "risk_label": risk_label,
                        },
                        parent_id=parent_id,
                        link_label="breached in",
                    )

                # Individual breach findings
                for breach in breaches_details:
                    breach_name = breach.get("breach", "Unknown")
                    breach_date = breach.get("xposed_date", "Unknown")
                    exposed_data = breach.get("xposed_data", [])
                    records = breach.get("xposed_records", 0)
                    industry = breach.get("industry", "Unknown")
                    password_risk = breach.get("passwordrisk", None)

                    severity = self._determine_severity(exposed_data, password_risk)

                    # Format exposed data for description
                    exposed_str = ", ".join(exposed_data[:5])
                    if len(exposed_data) > 5:
                        exposed_str += f" (+{len(exposed_data) - 5} more)"

                    description = f"Exposed: {exposed_str}"
                    if password_risk:
                        description += f" | Password Risk: {password_risk}"

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=severity,
                        title=f"Breach: {breach_name}",
                        description=description,
                        source="XposedOrNot",
                        source_url=f"https://xposedornot.com",
                        timestamp=datetime.utcnow(),
                        data={
                            "breach_name": breach_name,
                            "breach_date": breach_date,
                            "exposed_data": exposed_data,
                            "records": records,
                            "industry": industry,
                            "password_risk": password_risk,
                        },
                        parent_id=parent_id,
                        link_label="exposed in",
                    )

                # Paste dump exposure
                paste_count = pastes.get("cnt", 0) if pastes else 0
                if paste_count > 0:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.BREACH,
                        severity=Severity.HIGH,
                        title=f"Found in {paste_count} Paste Dump(s)",
                        description="Email appeared in public paste sites",
                        source="XposedOrNot",
                        timestamp=datetime.utcnow(),
                        data={
                            "paste_count": paste_count,
                            "sources": pastes.get("domain", []) if pastes else [],
                        },
                        parent_id=parent_id,
                        link_label="dumped in",
                    )

            except httpx.TimeoutException:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.LOW,
                    title="Breach Check Timeout",
                    description="Request timed out, try again later",
                    source="XposedOrNot",
                    timestamp=datetime.utcnow(),
                    data={"status": "timeout"},
                    parent_id=parent_id,
                    link_label="timeout",
                )

            except Exception as e:
                print(f"[BreachLookup] Error: {e}")
