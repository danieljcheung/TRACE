"""
Deep GitHub profile and commit analysis.
Extracts: commit emails, org memberships, linked socials, timezone inference.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime
from collections import Counter

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity
from config import settings


class GitHubLookup(OSINTModule):
    name = "GitHub Deep Scan"
    description = "Deep GitHub profile analysis including commit emails"

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "User-Agent": "TRACE-OSINT",
            "Accept": "application/vnd.github.v3+json",
        }
        if settings.GITHUB_TOKEN:
            self.headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

    async def _get_commit_emails(self, client: httpx.AsyncClient, username: str) -> list[dict]:
        """Extract unique emails from user's commit history."""
        emails = []
        seen = set()

        try:
            # Get user's repos
            resp = await client.get(
                f"https://api.github.com/users/{username}/repos",
                params={"sort": "pushed", "per_page": 10},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return emails

            repos = resp.json()

            for repo in repos[:5]:  # Check top 5 most recent repos
                repo_name = repo.get("full_name")
                if not repo_name:
                    continue

                # Get commits
                try:
                    commits_resp = await client.get(
                        f"https://api.github.com/repos/{repo_name}/commits",
                        params={"author": username, "per_page": 30},
                        timeout=self.timeout,
                    )
                    if commits_resp.status_code != 200:
                        continue

                    commits = commits_resp.json()

                    for commit in commits:
                        commit_data = commit.get("commit", {})
                        author = commit_data.get("author", {})
                        email = author.get("email", "")
                        name = author.get("name", "")

                        # Skip GitHub noreply emails
                        if email and "noreply" not in email.lower() and email not in seen:
                            seen.add(email)
                            emails.append({
                                "email": email,
                                "name": name,
                                "repo": repo_name,
                                "date": author.get("date"),
                            })

                except Exception:
                    continue

        except Exception as e:
            print(f"[GitHub] Commit email extraction error: {e}")

        return emails

    async def _get_organizations(self, client: httpx.AsyncClient, username: str) -> list[dict]:
        """Get user's organization memberships."""
        orgs = []
        try:
            resp = await client.get(
                f"https://api.github.com/users/{username}/orgs",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                for org in resp.json():
                    orgs.append({
                        "login": org.get("login"),
                        "url": f"https://github.com/{org.get('login')}",
                        "avatar": org.get("avatar_url"),
                        "description": org.get("description"),
                    })
        except Exception:
            pass
        return orgs

    async def _get_contribution_stats(self, client: httpx.AsyncClient, username: str) -> dict:
        """Analyze contribution patterns for timezone inference."""
        stats = {
            "total_repos": 0,
            "total_stars": 0,
            "languages": [],
            "commit_hours": [],
        }

        try:
            # Get repos for language analysis
            resp = await client.get(
                f"https://api.github.com/users/{username}/repos",
                params={"per_page": 100},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                repos = resp.json()
                stats["total_repos"] = len(repos)
                stats["total_stars"] = sum(r.get("stargazers_count", 0) for r in repos)

                # Collect languages
                languages = Counter()
                for repo in repos:
                    lang = repo.get("language")
                    if lang:
                        languages[lang] += 1
                stats["languages"] = [{"name": k, "count": v} for k, v in languages.most_common(5)]

            # Get events for activity timing
            resp = await client.get(
                f"https://api.github.com/users/{username}/events/public",
                params={"per_page": 100},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                events = resp.json()
                hours = []
                for event in events:
                    created = event.get("created_at")
                    if created:
                        try:
                            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                            hours.append(dt.hour)
                        except Exception:
                            pass
                stats["commit_hours"] = hours

        except Exception:
            pass

        return stats

    def _infer_timezone(self, commit_hours: list[int]) -> str | None:
        """Infer timezone from commit hour patterns."""
        if not commit_hours or len(commit_hours) < 10:
            return None

        # Find the most common hours
        hour_counts = Counter(commit_hours)
        most_common = hour_counts.most_common(5)

        # If activity clusters around certain hours, estimate timezone
        # Assume typical work hours are 9-18 local time
        peak_hours = [h for h, _ in most_common[:3]]
        avg_peak = sum(peak_hours) / len(peak_hours)

        # If peak is around 14-18 UTC, likely US West Coast (UTC-8)
        # If peak is around 17-21 UTC, likely US East Coast (UTC-5)
        # If peak is around 9-13 UTC, likely Europe (UTC+0/+1)
        # If peak is around 1-5 UTC, likely Asia Pacific (UTC+8/+9)

        if 14 <= avg_peak <= 18:
            return "Likely US West Coast (UTC-7/-8)"
        elif 17 <= avg_peak <= 22:
            return "Likely US East Coast (UTC-4/-5)"
        elif 9 <= avg_peak <= 14:
            return "Likely Europe (UTC+0/+1)"
        elif 1 <= avg_peak <= 6:
            return "Likely Asia Pacific (UTC+8/+9)"
        elif 6 <= avg_peak <= 9:
            return "Likely India/Middle East (UTC+5/+6)"

        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Deep GitHub profile analysis."""

        username = seed.lower().strip()
        if not username:
            return

        async with httpx.AsyncClient(headers=self.headers) as client:
            try:
                # Get user profile
                resp = await client.get(
                    f"https://api.github.com/users/{username}",
                    timeout=self.timeout,
                )

                if resp.status_code != 200:
                    return

                data = resp.json()
                profile_url = data.get("html_url", f"https://github.com/{username}")

                # Build rich description
                repos = data.get("public_repos", 0)
                followers = data.get("followers", 0)
                location = data.get("location", "")
                company = data.get("company", "")

                desc_parts = [f"{repos} repos", f"{followers} followers"]
                if location:
                    desc_parts.append(location)
                if company:
                    desc_parts.append(company)

                # Main profile finding
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.ACCOUNT,
                    severity=Severity.MEDIUM,
                    title=f"GitHub: {username} ({', '.join(desc_parts[:3])})",
                    description=f"Active GitHub account with {repos} public repositories",
                    source="GitHub API",
                    source_url=profile_url,
                    timestamp=datetime.utcnow(),
                    data={
                        "username": username,
                        "url": profile_url,
                        "repos": repos,
                        "followers": followers,
                        "following": data.get("following", 0),
                        "created": data.get("created_at"),
                        "avatar_url": data.get("avatar_url"),
                    },
                    parent_id=parent_id,
                    link_label="profile on",
                )

                # Real name (HIGH severity - PII)
                name = data.get("name")
                if name and name.lower() != username.lower():
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Real Name: {name}",
                        description="Name from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"name": name, "source": "github_profile"},
                        parent_id=parent_id,
                        link_label="real name",
                    )

                # Location
                if location:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.MEDIUM,
                        title=f"Location: {location}",
                        description="Location from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"location": location, "source": "github_profile", "confidence": "high"},
                        parent_id=parent_id,
                        link_label="located in",
                    )

                # Company/Employer
                if company:
                    # Clean up company name (remove @ if present)
                    company_clean = company.lstrip("@").strip()
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Employer: {company_clean}",
                        description="Company from GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"company": company_clean, "raw": company},
                        parent_id=parent_id,
                        link_label="works at",
                    )

                # Public email from profile
                email = data.get("email")
                if email:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.HIGH,
                        title=f"Public Email: {email}",
                        description="Email publicly displayed on GitHub profile",
                        source="GitHub",
                        source_url=profile_url,
                        timestamp=datetime.utcnow(),
                        data={"email": email, "source": "github_profile"},
                        parent_id=parent_id,
                        link_label="email on",
                    )

                # Twitter handle (linked social)
                twitter = data.get("twitter_username")
                if twitter:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"Linked Twitter: @{twitter}",
                        description="Twitter account linked on GitHub profile",
                        source="GitHub",
                        source_url=f"https://twitter.com/{twitter}",
                        timestamp=datetime.utcnow(),
                        data={"twitter": twitter, "url": f"https://twitter.com/{twitter}"},
                        parent_id=parent_id,
                        link_label="links to",
                    )

                # Blog/Website
                blog = data.get("blog")
                if blog:
                    if not blog.startswith(('http://', 'https://')):
                        blog = f"https://{blog}"

                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.MEDIUM,
                        title=f"Website: {blog}",
                        description="Personal website linked on GitHub profile",
                        source="GitHub",
                        source_url=blog,
                        timestamp=datetime.utcnow(),
                        data={"url": blog, "type": "personal_website"},
                        parent_id=parent_id,
                        link_label="website",
                    )

                # Bio analysis
                bio = data.get("bio")
                if bio:
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.PERSONAL_INFO,
                        severity=Severity.LOW,
                        title="Bio",
                        description=bio[:200] + ("..." if len(bio) > 200 else ""),
                        source="GitHub",
                        timestamp=datetime.utcnow(),
                        data={"bio": bio},
                        parent_id=parent_id,
                        link_label="bio from",
                    )

                # === DEEP SCAN (depth >= 2) ===
                if depth >= 2:
                    # Extract commit emails
                    commit_emails = await self._get_commit_emails(client, username)
                    for ce in commit_emails:
                        email_addr = ce["email"]
                        # Skip if same as profile email
                        if email and email_addr.lower() == email.lower():
                            continue

                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.HIGH,
                            title=f"Commit Email: {email_addr}",
                            description=f"Email found in commit history ({ce.get('name', 'unknown')})",
                            source="GitHub Commits",
                            source_url=f"https://github.com/{ce.get('repo', username)}",
                            timestamp=datetime.utcnow(),
                            data={
                                "email": email_addr,
                                "commit_name": ce.get("name"),
                                "repo": ce.get("repo"),
                                "source": "git_commit",
                            },
                            parent_id=parent_id,
                            link_label="commits as",
                        )

                    # Get organizations
                    orgs = await self._get_organizations(client, username)
                    for org in orgs:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.LOW,
                            title=f"Org: {org['login']}",
                            description=org.get("description") or "GitHub organization member",
                            source="GitHub",
                            source_url=org["url"],
                            timestamp=datetime.utcnow(),
                            data=org,
                            parent_id=parent_id,
                            link_label="member of",
                        )

                    # Contribution stats and timezone inference
                    stats = await self._get_contribution_stats(client, username)

                    if stats["languages"]:
                        top_langs = ", ".join(l["name"] for l in stats["languages"][:3])
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.LOW,
                            title=f"Primary Languages: {top_langs}",
                            description=f"Most used programming languages across {stats['total_repos']} repos",
                            source="GitHub Analysis",
                            timestamp=datetime.utcnow(),
                            data={
                                "languages": stats["languages"],
                                "total_repos": stats["total_repos"],
                                "total_stars": stats["total_stars"],
                            },
                            parent_id=parent_id,
                            link_label="codes in",
                        )

                    # Timezone inference
                    tz_guess = self._infer_timezone(stats.get("commit_hours", []))
                    if tz_guess:
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Timezone: {tz_guess}",
                            description="Timezone inferred from commit activity patterns",
                            source="GitHub Activity Analysis",
                            timestamp=datetime.utcnow(),
                            data={
                                "timezone_guess": tz_guess,
                                "sample_size": len(stats.get("commit_hours", [])),
                                "confidence": "medium",
                            },
                            parent_id=parent_id,
                            link_label="active in",
                        )

            except Exception as e:
                print(f"[GitHub] Error: {e}")
