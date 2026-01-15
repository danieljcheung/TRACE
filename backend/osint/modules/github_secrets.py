"""
GitHub secrets scanner - searches for accidentally committed secrets and PII.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity
from config import settings


class GitHubSecrets(OSINTModule):
    name = "GitHub Secrets Scanner"
    description = "Scan GitHub repos for exposed secrets and personal info"

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "TRACE-OSINT",
        }
        if settings.GITHUB_TOKEN:
            self.headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

    # Patterns to search for
    SECRET_PATTERNS = [
        # Environment files
        ("filename:.env", "Environment File", Severity.CRITICAL),
        ("filename:.env.local", "Local Env File", Severity.CRITICAL),
        ("filename:.env.production", "Production Env", Severity.CRITICAL),

        # Config files with secrets
        ("filename:config.json password", "Config Password", Severity.CRITICAL),
        ("filename:settings.py SECRET", "Django Secret", Severity.HIGH),
        ("filename:credentials", "Credentials File", Severity.CRITICAL),

        # API keys
        ("api_key", "API Key", Severity.HIGH),
        ("apikey", "API Key", Severity.HIGH),
        ("api_secret", "API Secret", Severity.CRITICAL),
        ("access_token", "Access Token", Severity.HIGH),

        # Cloud credentials
        ("AWS_SECRET", "AWS Secret", Severity.CRITICAL),
        ("AZURE_", "Azure Credential", Severity.HIGH),
        ("GOOGLE_APPLICATION_CREDENTIALS", "GCP Credentials", Severity.CRITICAL),

        # Database
        ("mongodb+srv://", "MongoDB URI", Severity.CRITICAL),
        ("postgres://", "Postgres URI", Severity.HIGH),
        ("mysql://", "MySQL URI", Severity.HIGH),

        # SSH/Private keys
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", Severity.CRITICAL),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "SSH Private Key", Severity.CRITICAL),
        ("filename:id_rsa", "SSH Key File", Severity.CRITICAL),

        # Personal info in code
        ("TODO phone", "Phone in Comments", Severity.MEDIUM),
        ("TODO address", "Address in Comments", Severity.MEDIUM),
        ("my phone", "Personal Phone", Severity.HIGH),
        ("my address", "Personal Address", Severity.HIGH),
    ]

    async def _search_github(
        self,
        client: httpx.AsyncClient,
        query: str,
        username: str
    ) -> list[dict]:
        """Search GitHub code for a query within user's repos."""
        results = []

        try:
            full_query = f"user:{username} {query}"

            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": full_query, "per_page": 10},
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", []):
                    results.append({
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "path": item.get("path", ""),
                        "url": item.get("html_url", ""),
                        "sha": item.get("sha", "")[:7],
                    })

            elif resp.status_code == 403:
                print("[GitHubSecrets] Rate limited")

        except Exception as e:
            print(f"[GitHubSecrets] Search error: {e}")

        return results

    async def _get_commit_emails(
        self,
        client: httpx.AsyncClient,
        username: str
    ) -> list[str]:
        """Extract unique emails from user's commit history."""
        emails = set()

        try:
            # Get user's repos
            resp = await client.get(
                f"https://api.github.com/users/{username}/repos",
                params={"sort": "pushed", "per_page": 5},
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                return list(emails)

            repos = resp.json()

            for repo in repos[:3]:
                repo_name = repo.get("full_name")
                if not repo_name:
                    continue

                # Get commits
                try:
                    commits_resp = await client.get(
                        f"https://api.github.com/repos/{repo_name}/commits",
                        params={"author": username, "per_page": 20},
                        headers=self.headers,
                        timeout=self.timeout,
                    )

                    if commits_resp.status_code == 200:
                        commits = commits_resp.json()
                        for commit in commits:
                            author = commit.get("commit", {}).get("author", {})
                            email = author.get("email", "")
                            if email and "noreply" not in email.lower():
                                emails.add(email)

                except Exception:
                    continue

                import asyncio
                await asyncio.sleep(0.3)

        except Exception as e:
            print(f"[GitHubSecrets] Commit email error: {e}")

        return list(emails)

    async def _scan_repo_contents(
        self,
        client: httpx.AsyncClient,
        repo: str
    ) -> list[dict]:
        """Scan repository root for sensitive files."""
        sensitive_files = []
        sensitive_names = [
            ".env", ".env.local", ".env.production", ".env.development",
            "config.json", "secrets.json", "credentials.json",
            ".htpasswd", ".netrc", ".npmrc", ".pypirc",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            "docker-compose.yml", "Dockerfile",
        ]

        try:
            resp = await client.get(
                f"https://api.github.com/repos/{repo}/contents",
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                contents = resp.json()
                for item in contents:
                    name = item.get("name", "").lower()
                    if any(sens.lower() in name for sens in sensitive_names):
                        sensitive_files.append({
                            "name": item.get("name"),
                            "path": item.get("path"),
                            "url": item.get("html_url"),
                            "type": item.get("type"),
                        })

        except Exception:
            pass

        return sensitive_files

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Scan GitHub for secrets and exposed personal info."""

        username = seed.strip().lower()
        if not username or "@" in username:
            # If email passed, extract username
            if "@" in username:
                username = username.split("@")[0]
            else:
                return

        async with httpx.AsyncClient() as client:
            # First check if user exists
            resp = await client.get(
                f"https://api.github.com/users/{username}",
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                return

            user_data = resp.json()
            repos_count = user_data.get("public_repos", 0)

            if repos_count == 0:
                return

            # Get commit emails
            commit_emails = await self._get_commit_emails(client, username)

            if commit_emails:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.HIGH,
                    title=f"Commit Emails: {len(commit_emails)} found",
                    description=f"Emails exposed in git history: {', '.join(commit_emails[:3])}",
                    source="GitHub Commits",
                    source_url=f"https://github.com/{username}",
                    timestamp=datetime.utcnow(),
                    data={
                        "emails": commit_emails,
                        "count": len(commit_emails),
                        "remediation": "Use GitHub's email privacy settings; rewrite git history to remove",
                    },
                    parent_id=parent_id,
                    link_label="emails in",
                )

            import asyncio
            await asyncio.sleep(1)

            # Search for secrets
            secrets_found = []

            for query, secret_type, severity in self.SECRET_PATTERNS[:10]:  # Limit searches
                results = await self._search_github(client, query, username)

                if results:
                    secrets_found.extend([
                        {**r, "type": secret_type, "severity": severity.value}
                        for r in results
                    ])

                    # Yield critical findings immediately
                    if severity == Severity.CRITICAL:
                        for result in results[:2]:
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.BREACH,
                                severity=Severity.CRITICAL,
                                title=f"Secret Exposed: {secret_type}",
                                description=f"Found in {result['repo']}/{result['path']}",
                                source="GitHub Secrets Scan",
                                source_url=result["url"],
                                timestamp=datetime.utcnow(),
                                data={
                                    "repo": result["repo"],
                                    "path": result["path"],
                                    "type": secret_type,
                                    "remediation": "Rotate credentials immediately; remove from git history",
                                },
                                parent_id=parent_id,
                                link_label="secret in",
                            )

                await asyncio.sleep(2)  # Rate limiting

            # Get user's repos and check for sensitive files
            resp = await client.get(
                f"https://api.github.com/users/{username}/repos",
                params={"sort": "pushed", "per_page": 10},
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                repos = resp.json()

                for repo in repos[:5]:
                    repo_name = repo.get("full_name")
                    sensitive = await self._scan_repo_contents(client, repo_name)

                    for file in sensitive:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.BREACH,
                            severity=Severity.HIGH,
                            title=f"Sensitive File: {file['name']}",
                            description=f"Found in {repo_name}",
                            source="GitHub Repo Scan",
                            source_url=file["url"],
                            timestamp=datetime.utcnow(),
                            data={
                                "file": file["name"],
                                "repo": repo_name,
                                "path": file["path"],
                                "remediation": "Review file contents; remove if contains secrets",
                            },
                            parent_id=parent_id,
                            link_label="sensitive file",
                        )

                    await asyncio.sleep(0.5)

            # Summary
            if secrets_found:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.BREACH,
                    severity=Severity.HIGH,
                    title=f"GitHub Secrets: {len(secrets_found)} potential exposures",
                    description="Credentials or sensitive data may be exposed in repositories",
                    source="GitHub Secrets Scan",
                    source_url=f"https://github.com/{username}",
                    timestamp=datetime.utcnow(),
                    data={
                        "total_findings": len(secrets_found),
                        "findings": secrets_found[:20],
                        "remediation": "Review all findings; rotate exposed credentials",
                    },
                    parent_id=parent_id,
                    link_label="secrets in",
                )
