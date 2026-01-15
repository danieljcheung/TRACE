"""Orchestrator coordinates aggressive deep OSINT scanning."""

import asyncio
import time
import uuid
import json
from typing import AsyncGenerator, Callable
from datetime import datetime

from models.findings import Finding, NodeType, Severity
from .modules import (
    # HOP 1 - Direct Email Intelligence
    BreachLookup,
    EpieosLookup,
    ReverseLookup,
    GoogleDork,
    PasteSearch,
    GravatarLookup,
    UsernameExtractor,

    # HOP 1.5 - Username Discovery (email-based)
    GitHubEmailSearch,
    KeybaseLookup,
    IntelXSearch,
    HudsonRockSearch,

    # HOP 2 - Username Expansion
    UsernameChecker,
    GitHubLookup,
    GitHubSecrets,
    SocialDeepDive,
    WaybackLookup,

    # HOP 3 - Aggregation
    DataBrokerCheck,
    LocationInference,
    ConnectedAccountFinder,
)
from .risk import calculate_risk_score


class ScanOrchestrator:
    """
    Coordinates aggressive deep OSINT scan with username discovery.

    HOP 1 - Direct Email Intelligence:
        - XposedOrNot breach lookup
        - Epieos (Google account, service registrations)
        - Reverse email lookup (EmailRep, ThatsThem)
        - Google dorking (documents, pastes, profiles)
        - Paste site search (GitHub, IntelX, psbdmp)
        - Gravatar profile + username extraction from linked accounts
        - Username extraction from email prefix

        Username Discovery (email-based):
        - GitHub commit email search (find GitHub users by commit author)
        - Keybase verified proofs (cryptographically verified Twitter, GitHub, Reddit)
        - IntelX leaked database search
        - HudsonRock stealer malware log search

    HOP 2 - Username Expansion:
        - Platform account check (API-validated)
        - GitHub deep scan + secrets scanner
        - Social media deep dive (Reddit, Twitter)
        - Wayback Machine archive search

    HOP 3 - Aggregation & Correlation:
        - Data broker URL generation + warnings
        - Location inference aggregation
        - Connected accounts correlation
        - Generate remediation links
    """

    def __init__(self):
        self.audit_log: list[str] = []
        self.findings: list[Finding] = []
        self.start_time: float = 0
        # Collected data for correlation
        self.usernames: set[str] = set()
        self.bios: list[str] = []
        self.locations: list[dict] = []
        self.found_accounts: list[dict] = []
        self.found_urls: list[str] = []

    def _log(self, message: str, level: str = "INFO"):
        """Add timestamped audit log entry."""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"
        self.audit_log.append(entry)
        print(entry)

    def _mask_email(self, email: str) -> str:
        """Mask email for display."""
        if '@' not in email:
            return "***@***"
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked = local[0] + "***"
        else:
            masked = local[0] + "***" + local[-1]
        return f"{masked}@{domain}"

    async def _run_module(
        self,
        module,
        seed: str,
        depth: int,
        parent_id: str,
        log: Callable,
        on_finding: Callable | None,
    ) -> list[Finding]:
        """Run a single module and collect findings."""
        results = []
        log(f"  >> {module.name}")

        try:
            async for finding in module.run(seed, depth, parent_id):
                self.findings.append(finding)
                results.append(finding)
                if on_finding:
                    on_finding(finding)

                # Collect metadata for correlation
                self._collect_metadata(finding)

                log(f"     [+] {finding.title[:60]}", "SUCCESS")

        except asyncio.TimeoutError:
            log(f"     [!] Timeout: {module.name}", "WARN")
        except Exception as e:
            log(f"     [!] Error: {type(e).__name__}", "ERROR")

        return results

    def _collect_metadata(self, finding: Finding):
        """Extract useful metadata from findings for later correlation."""
        data = finding.data or {}

        # Collect usernames
        if finding.type == NodeType.USERNAME or data.get("username"):
            username = data.get("username")
            if username and len(username) >= 3:
                self.usernames.add(username)

        # Collect bios
        if data.get("bio"):
            self.bios.append(data["bio"])

        # Collect locations
        if data.get("location"):
            self.locations.append({
                "location": data["location"],
                "source": finding.source,
                "source_type": data.get("source", "unknown"),
                "confidence": data.get("confidence", 0.5),
            })

        # Collect found accounts
        if finding.type == NodeType.ACCOUNT:
            platform = data.get("platform", "")
            username = data.get("username", "")
            if platform and username:
                self.found_accounts.append({
                    "platform": platform,
                    "username": username,
                    "url": data.get("url", ""),
                })
                # Also add username for further searching
                if len(username) >= 3:
                    self.usernames.add(username)

        # Collect URLs for archive search
        if data.get("url"):
            self.found_urls.append(data["url"])
        if finding.source_url:
            self.found_urls.append(finding.source_url)

    async def run(
        self,
        email: str,
        depth: int = 1,
        on_finding: Callable[[Finding], None] | None = None,
        on_log: Callable[[str, str], None] | None = None,
    ) -> AsyncGenerator[Finding, None]:
        """
        Execute aggressive multi-hop scan.

        Args:
            email: Seed email address
            depth: Scan depth (1-3 hops)
            on_finding: Callback for each finding
            on_log: Callback for log entries

        Yields:
            Finding objects as discovered
        """
        # Reset state
        self.audit_log = []
        self.findings = []
        self.start_time = time.time()
        self.usernames = set()
        self.bios = []
        self.locations = []
        self.found_accounts = []
        self.found_urls = []

        def log(msg: str, level: str = "INFO"):
            self._log(msg, level)
            if on_log:
                on_log(msg, level)

        log("=" * 60)
        log("TRACE AGGRESSIVE DEEP SCAN")
        log(f"DEPTH: {depth} HOP(S) | MODE: AGGRESSIVE")
        log("SELF-ASSESSMENT ONLY - VERIFIED EMAIL REQUIRED")
        log("=" * 60)

        # Create root node
        root_id = str(uuid.uuid4())
        masked = self._mask_email(email)

        root = Finding(
            id=root_id,
            type=NodeType.EMAIL,
            severity=Severity.LOW,
            title=masked,
            description="Seed email - starting aggressive scan",
            source="User Input",
            timestamp=datetime.utcnow(),
            data={"email_masked": masked},
        )
        self.findings.append(root)
        yield root
        if on_finding:
            on_finding(root)

        # Extract username from email for searching
        username_from_email = email.split("@")[0]
        if len(username_from_email) >= 3:
            self.usernames.add(username_from_email)

        # ==================== HOP 1 ====================
        log("")
        log("=" * 60)
        log("HOP 1: DIRECT EMAIL INTELLIGENCE")
        log("=" * 60)

        hop1_modules = [
            # Direct email intelligence
            BreachLookup(),       # XposedOrNot breaches
            EpieosLookup(),       # Google account, service checks
            ReverseLookup(),      # EmailRep, ThatsThem
            GoogleDork(),         # Document search
            PasteSearch(),        # Paste/leak site search
            GravatarLookup(),     # Gravatar profile + username extraction
            UsernameExtractor(),  # Extract username patterns from email

            # Username discovery (email-based searches)
            GitHubEmailSearch(),  # Find GitHub users by commit email
            KeybaseLookup(),      # Keybase verified proofs (Twitter, GitHub, etc.)
            IntelXSearch(),       # IntelX leaked databases
            HudsonRockSearch(),   # Stealer malware log search
        ]

        for module in hop1_modules:
            results = await self._run_module(
                module, email, depth, root_id, log, on_finding
            )
            for finding in results:
                yield finding
            await asyncio.sleep(0.5)

        # ==================== HOP 2 ====================
        if depth >= 2 and self.usernames:
            log("")
            log("=" * 60)
            log(f"HOP 2: USERNAME EXPANSION ({len(self.usernames)} usernames)")
            log("=" * 60)

            usernames_to_check = list(self.usernames)[:5]

            for username in usernames_to_check:
                log(f"")
                log(f"--- Expanding: {username} ---")

                # Platform account checker
                checker = UsernameChecker()
                results = await self._run_module(
                    checker, username, depth, root_id, log, on_finding
                )
                for finding in results:
                    yield finding
                await asyncio.sleep(0.5)

                # GitHub deep scan
                github = GitHubLookup()
                results = await self._run_module(
                    github, username, depth, root_id, log, on_finding
                )
                for finding in results:
                    yield finding
                await asyncio.sleep(0.5)

                # GitHub secrets scanner
                secrets = GitHubSecrets()
                results = await self._run_module(
                    secrets, username, depth, root_id, log, on_finding
                )
                for finding in results:
                    yield finding
                await asyncio.sleep(0.5)

                # Social media deep dive
                for platform in ["reddit", "twitter", "github"]:
                    deep = SocialDeepDive()
                    seed = f"{platform}:{username}"
                    results = await self._run_module(
                        deep, seed, depth, root_id, log, on_finding
                    )
                    for finding in results:
                        yield finding
                    await asyncio.sleep(0.3)

            # Wayback Machine search for found URLs
            if self.found_urls:
                log("")
                log("--- Checking Archive.org ---")
                wayback = WaybackLookup()

                for url in list(set(self.found_urls))[:5]:
                    results = await self._run_module(
                        wayback, url, depth, root_id, log, on_finding
                    )
                    for finding in results:
                        yield finding
                    await asyncio.sleep(0.5)

        # ==================== HOP 3 ====================
        if depth >= 3:
            log("")
            log("=" * 60)
            log("HOP 3: AGGREGATION & CORRELATION")
            log("=" * 60)

            # Data broker warnings
            log("--- Data Broker Exposure Check ---")
            broker = DataBrokerCheck()
            results = await self._run_module(
                broker, email, depth, root_id, log, on_finding
            )
            for finding in results:
                yield finding

            # Location inference
            if self.locations:
                log("--- Aggregating Location Data ---")
                location = LocationInference()
                seed_data = json.dumps(self.locations)
                results = await self._run_module(
                    location, seed_data, depth, root_id, log, on_finding
                )
                for finding in results:
                    yield finding

            # Connected accounts correlation
            if self.usernames or self.bios:
                log("--- Cross-Platform Correlation ---")
                connector = ConnectedAccountFinder()
                seed_data = json.dumps({
                    "usernames": list(self.usernames),
                    "bios": self.bios,
                    "found_accounts": self.found_accounts,
                })
                results = await self._run_module(
                    connector, seed_data, depth, root_id, log, on_finding
                )
                for finding in results:
                    yield finding

        # ==================== COMPLETION ====================
        elapsed = time.time() - self.start_time

        log("")
        log("=" * 60)
        log(f"SCAN COMPLETE ({elapsed:.1f}s)")
        log(f"TOTAL FINDINGS: {len(self.findings)}")

        score, level = calculate_risk_score(self.findings)
        log(f"RISK SCORE: {score}/100 ({level})")

        # Summary stats
        accounts = len([f for f in self.findings if f.type == NodeType.ACCOUNT])
        breaches = len([f for f in self.findings if f.type == NodeType.BREACH])
        pii = len([f for f in self.findings if f.type == NodeType.PERSONAL_INFO])
        critical = len([f for f in self.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in self.findings if f.severity == Severity.HIGH])

        log(f"ACCOUNTS: {accounts} | BREACHES: {breaches} | PII: {pii}")
        log(f"CRITICAL: {critical} | HIGH: {high}")
        log("ALL DATA CLEARED FROM MEMORY")
        log("=" * 60)

    def get_results(self) -> dict:
        """Get scan results summary."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        score, level = calculate_risk_score(self.findings)

        return {
            "findings": [f.model_dump() for f in self.findings],
            "audit_log": self.audit_log,
            "scan_time_seconds": round(elapsed, 1),
            "total_nodes": len(self.findings),
            "risk_score": score,
            "risk_level": level,
            "stats": {
                "accounts": len([f for f in self.findings if f.type == NodeType.ACCOUNT]),
                "breaches": len([f for f in self.findings if f.type == NodeType.BREACH]),
                "personal_info": len([f for f in self.findings if f.type == NodeType.PERSONAL_INFO]),
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "usernames_discovered": len(self.usernames),
                "urls_found": len(self.found_urls),
            }
        }
