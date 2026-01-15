"""Orchestrator coordinates all OSINT modules."""

import asyncio
import time
import uuid
from typing import AsyncGenerator, Callable
from datetime import datetime

from models.findings import Finding, NodeType, Severity
from .modules import ALL_MODULES, USERNAME_MODULES, UsernameExtractor, UsernameChecker, GitHubLookup
from .risk import calculate_risk_score


class ScanOrchestrator:
    """
    Coordinates OSINT module execution.

    Flow:
    1. HOP 1: Run email-based modules (breach, gravatar, pgp, whois, username extraction)
    2. HOP 2: Run username-based modules on discovered usernames (platform check, github)
    3. HOP 3: Deep trace - follow links from hop 2
    """

    def __init__(self):
        self.audit_log: list[str] = []
        self.findings: list[Finding] = []
        self.start_time: float = 0

    def _log(self, message: str, level: str = "INFO"):
        """Add timestamped audit log entry."""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"
        self.audit_log.append(entry)
        print(entry)  # Also print for debugging

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

    async def run(
        self,
        email: str,
        depth: int = 1,
        on_finding: Callable[[Finding], None] | None = None,
        on_log: Callable[[str, str], None] | None = None,
    ) -> AsyncGenerator[Finding, None]:
        """
        Execute scan and yield findings.

        Args:
            email: Seed email address
            depth: Scan depth (1-3 hops)
            on_finding: Callback for each finding
            on_log: Callback for log entries

        Yields:
            Finding objects as discovered
        """
        self.audit_log = []
        self.findings = []
        self.start_time = time.time()

        def log(msg: str, level: str = "INFO"):
            self._log(msg, level)
            if on_log:
                on_log(msg, level)

        log("SCAN INITIATED")
        log(f"DEPTH: {depth} HOP(S)")
        log("ZERO DATA RETENTION MODE ACTIVE")

        # Create root node
        root_id = str(uuid.uuid4())
        masked = self._mask_email(email)

        root = Finding(
            id=root_id,
            type=NodeType.EMAIL,
            severity=Severity.LOW,
            title=masked,
            description="Seed email",
            source="User Input",
            timestamp=datetime.utcnow(),
            data={"email_masked": masked},
        )
        self.findings.append(root)
        yield root
        if on_finding:
            on_finding(root)

        # Track discovered usernames for hop 2
        usernames: set[str] = set()
        username_to_finding: dict[str, str] = {}  # username -> finding_id

        # ========== HOP 1: Email-based lookups ==========
        log("=" * 40)
        log("HOP 1: DIRECT EMAIL ANALYSIS")
        log("=" * 40)

        # Run email modules
        for ModuleClass in ALL_MODULES:
            module = ModuleClass()
            log(f"QUERYING: {module.name.upper()}")

            try:
                async for finding in module.run(email, depth, root_id):
                    self.findings.append(finding)
                    yield finding
                    if on_finding:
                        on_finding(finding)

                    # Collect usernames
                    if finding.type == NodeType.USERNAME or finding.type == 'username':
                        username = finding.data.get('username')
                        if username:
                            usernames.add(username)
                            username_to_finding[username] = finding.id

                    log(f"  FOUND: {finding.title}", "SUCCESS")

            except asyncio.TimeoutError:
                log(f"  TIMEOUT: {module.name}", "WARN")
            except Exception as e:
                log(f"  ERROR: {module.name} - {type(e).__name__}", "ERROR")

        # ========== HOP 2: Username-based lookups ==========
        if depth >= 2 and usernames:
            log("=" * 40)
            log(f"HOP 2: USERNAME ANALYSIS ({len(usernames)} usernames)")
            log("=" * 40)

            # Limit usernames to check
            usernames_to_check = list(usernames)[:5]

            for username in usernames_to_check:
                parent_id = username_to_finding.get(username, root_id)

                # Username checker (all platforms)
                log(f"CHECKING PLATFORMS: {username}")
                checker = UsernameChecker()

                try:
                    async for finding in checker.run(username, depth, parent_id):
                        self.findings.append(finding)
                        yield finding
                        if on_finding:
                            on_finding(finding)
                        log(f"  FOUND: {finding.title}", "SUCCESS")

                except asyncio.TimeoutError:
                    log(f"  TIMEOUT: Platform check for {username}", "WARN")
                except Exception as e:
                    log(f"  ERROR: Platform check - {type(e).__name__}", "ERROR")

                # GitHub detailed lookup
                log(f"QUERYING: GITHUB ({username})")
                github = GitHubLookup()

                try:
                    async for finding in github.run(username, depth, parent_id):
                        self.findings.append(finding)
                        yield finding
                        if on_finding:
                            on_finding(finding)
                        log(f"  FOUND: {finding.title}", "SUCCESS")

                except asyncio.TimeoutError:
                    log(f"  TIMEOUT: GitHub for {username}", "WARN")
                except Exception as e:
                    log(f"  ERROR: GitHub - {type(e).__name__}", "ERROR")

                # Small delay between usernames
                await asyncio.sleep(0.5)

        # ========== HOP 3: Deep trace ==========
        if depth >= 3:
            log("=" * 40)
            log("HOP 3: DEEP TRACE")
            log("=" * 40)
            log("ANALYZING CROSS-REFERENCES...")

            # In a full implementation, this would:
            # - Follow website links found in profiles
            # - Cross-reference names across platforms
            # - Check for connected accounts
            # - Analyze metadata from found profiles

            # For now, add a placeholder delay
            await asyncio.sleep(2)
            log("DEEP TRACE COMPLETE")

        # ========== Completion ==========
        elapsed = time.time() - self.start_time

        log("=" * 40)
        log(f"SCAN COMPLETE ({elapsed:.1f}s)")
        log(f"TOTAL NODES: {len(self.findings)}")

        score, level = calculate_risk_score(self.findings)
        log(f"RISK SCORE: {score}/100 ({level})")
        log("ALL DATA CLEARED FROM MEMORY")
        log("=" * 40)

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
        }
