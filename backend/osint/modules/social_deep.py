"""
Social media deep dive - extracts detailed info from found social accounts.
"""

import httpx
import uuid
import re
import hashlib
from typing import AsyncGenerator
from datetime import datetime
from collections import Counter

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class SocialDeepDive(OSINTModule):
    name = "Social Media Deep Dive"
    description = "Extract detailed info from social profiles"

    # Location-indicating subreddits
    LOCATION_SUBREDDITS = {
        "nyc": "New York City", "newyorkcity": "New York City",
        "losangeles": "Los Angeles", "sanfrancisco": "San Francisco",
        "seattle": "Seattle", "chicago": "Chicago", "boston": "Boston",
        "austin": "Austin", "denver": "Denver", "portland": "Portland",
        "philadelphia": "Philadelphia", "atlanta": "Atlanta",
        "miami": "Miami", "dallas": "Dallas", "houston": "Houston",
        "london": "London, UK", "toronto": "Toronto",
        "vancouver": "Vancouver", "sydney": "Sydney",
        "melbourne": "Melbourne", "berlin": "Berlin",
        "amsterdam": "Amsterdam", "paris": "Paris",
        "singapore": "Singapore", "tokyo": "Tokyo",
        "bangalore": "Bangalore", "mumbai": "Mumbai",
    }

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

    def _extract_personal_info(self, text: str) -> dict:
        """Extract phone numbers, emails, usernames from text."""
        info = {}

        # Phone numbers
        phone_patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b',
            r'\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b',
        ]
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            if matches:
                info["phones"] = list(set(matches))[:3]
                break

        # Usernames mentioned (@ mentions)
        usernames = re.findall(r'@([a-zA-Z0-9_]{3,30})', text)
        if usernames:
            info["mentioned_usernames"] = list(set(usernames))[:10]

        # URLs
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        if urls:
            info["urls"] = list(set(urls))[:10]

        # Social links
        social_patterns = [
            (r'twitter\.com/([a-zA-Z0-9_]+)', "twitter"),
            (r'instagram\.com/([a-zA-Z0-9_.]+)', "instagram"),
            (r'linkedin\.com/in/([a-zA-Z0-9-]+)', "linkedin"),
            (r'github\.com/([a-zA-Z0-9-]+)', "github"),
            (r'youtube\.com/(?:c/|channel/|user/|@)([a-zA-Z0-9_-]+)', "youtube"),
            (r't\.me/([a-zA-Z0-9_]+)', "telegram"),
        ]
        social_links = []
        for pattern, platform in social_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                social_links.append({"platform": platform, "username": match})
        if social_links:
            info["social_links"] = social_links

        return info

    async def _scrape_reddit(
        self,
        client: httpx.AsyncClient,
        username: str
    ) -> dict | None:
        """Deep scrape Reddit profile."""
        try:
            # Get user about
            resp = await client.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "TRACE-OSINT/1.0"},
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})

            result = {
                "karma": data.get("total_karma", 0),
                "created_utc": data.get("created_utc"),
                "is_gold": data.get("is_gold", False),
            }

            # Get recent comments for analysis
            comments_resp = await client.get(
                f"https://www.reddit.com/user/{username}/comments.json",
                params={"limit": 100},
                headers={"User-Agent": "TRACE-OSINT/1.0"},
                timeout=self.timeout,
            )

            if comments_resp.status_code == 200:
                comments_data = comments_resp.json().get("data", {}).get("children", [])

                subreddits = Counter()
                comment_text = []

                for comment in comments_data:
                    c_data = comment.get("data", {})
                    sub = c_data.get("subreddit", "").lower()
                    body = c_data.get("body", "")

                    if sub:
                        subreddits[sub] += 1
                    if body:
                        comment_text.append(body[:500])

                # Location hints from subreddits
                location_hints = []
                for sub, count in subreddits.most_common(30):
                    if sub in self.LOCATION_SUBREDDITS:
                        location_hints.append({
                            "location": self.LOCATION_SUBREDDITS[sub],
                            "subreddit": sub,
                            "posts": count,
                        })

                result["top_subreddits"] = dict(subreddits.most_common(10))
                result["location_hints"] = location_hints

                # Extract personal info from comments
                all_text = " ".join(comment_text)
                extracted = self._extract_personal_info(all_text)
                if extracted:
                    result["extracted_info"] = extracted

            return result

        except Exception as e:
            print(f"[SocialDeep] Reddit error: {e}")
            return None

    async def _scrape_twitter_nitter(
        self,
        client: httpx.AsyncClient,
        username: str
    ) -> dict | None:
        """Scrape Twitter via Nitter instances."""
        nitter_instances = [
            "nitter.net",
            "nitter.it",
            "nitter.privacydev.net",
        ]

        for instance in nitter_instances:
            try:
                resp = await client.get(
                    f"https://{instance}/{username}",
                    timeout=self.timeout,
                    follow_redirects=True,
                )

                if resp.status_code == 200:
                    html = resp.text

                    result = {}

                    # Extract bio
                    bio_match = re.search(r'<p class="profile-bio"[^>]*>(.*?)</p>', html, re.DOTALL)
                    if bio_match:
                        bio = re.sub(r'<[^>]+>', '', bio_match.group(1)).strip()
                        result["bio"] = bio

                        # Extract info from bio
                        extracted = self._extract_personal_info(bio)
                        if extracted:
                            result["extracted_info"] = extracted

                    # Extract location
                    loc_match = re.search(r'<span class="profile-location"[^>]*>.*?<span[^>]*>(.*?)</span>', html, re.DOTALL)
                    if loc_match:
                        location = re.sub(r'<[^>]+>', '', loc_match.group(1)).strip()
                        if location:
                            result["location"] = location

                    # Extract website
                    web_match = re.search(r'<a class="profile-website"[^>]*href="([^"]+)"', html)
                    if web_match:
                        result["website"] = web_match.group(1)

                    # Extract join date
                    join_match = re.search(r'Joined\s+([A-Za-z]+\s+\d{4})', html)
                    if join_match:
                        result["joined"] = join_match.group(1)

                    # Extract follower counts
                    followers_match = re.search(r'<span class="profile-stat-num"[^>]*>([\d,]+)</span>\s*<span[^>]*>Followers', html)
                    if followers_match:
                        result["followers"] = int(followers_match.group(1).replace(",", ""))

                    if result:
                        return result

            except Exception:
                continue

        return None

    async def _scrape_github_deep(
        self,
        client: httpx.AsyncClient,
        username: str
    ) -> dict | None:
        """Deep scrape GitHub profile."""
        try:
            resp = await client.get(
                f"https://api.github.com/users/{username}",
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "TRACE-OSINT",
                },
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                return None

            data = resp.json()

            result = {
                "name": data.get("name"),
                "company": data.get("company"),
                "location": data.get("location"),
                "email": data.get("email"),
                "bio": data.get("bio"),
                "blog": data.get("blog"),
                "twitter": data.get("twitter_username"),
                "repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "created": data.get("created_at"),
                "avatar_url": data.get("avatar_url"),
            }

            # Extract info from bio
            if result.get("bio"):
                extracted = self._extract_personal_info(result["bio"])
                if extracted:
                    result["extracted_info"] = extracted

            # Hash avatar for correlation
            if result.get("avatar_url"):
                try:
                    avatar_resp = await client.get(result["avatar_url"], timeout=10.0)
                    if avatar_resp.status_code == 200:
                        result["avatar_hash"] = hashlib.md5(avatar_resp.content).hexdigest()
                except Exception:
                    pass

            return result

        except Exception as e:
            print(f"[SocialDeep] GitHub error: {e}")
            return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Deep dive into social media profile.
        Seed format: "platform:username" (e.g., "reddit:johndoe")
        """

        if ':' not in seed:
            return

        platform, username = seed.split(':', 1)
        platform = platform.lower().strip()
        username = username.strip()

        if not username:
            return

        async with httpx.AsyncClient(headers=self.headers) as client:

            # Reddit deep scrape
            if platform == "reddit":
                data = await self._scrape_reddit(client, username)

                if data:
                    # Location hints
                    if data.get("location_hints"):
                        top_hint = max(data["location_hints"], key=lambda x: x["posts"])
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location (Reddit): {top_hint['location']}",
                            description=f"Inferred from r/{top_hint['subreddit']} activity",
                            source="Reddit Analysis",
                            source_url=f"https://reddit.com/u/{username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "location": top_hint["location"],
                                "confidence": "medium" if top_hint["posts"] > 5 else "low",
                                "all_hints": data["location_hints"],
                            },
                            parent_id=parent_id,
                            link_label="likely in",
                        )

                    # Extracted personal info
                    if data.get("extracted_info"):
                        info = data["extracted_info"]

                        if info.get("phones"):
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.PERSONAL_INFO,
                                severity=Severity.HIGH,
                                title=f"Phone Number in Posts",
                                description=f"Found in Reddit comments",
                                source="Reddit Analysis",
                                timestamp=datetime.utcnow(),
                                data={
                                    "phones": info["phones"],
                                    "remediation": "Edit or delete posts containing phone number",
                                },
                                parent_id=parent_id,
                                link_label="phone found",
                            )

                        if info.get("social_links"):
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.ACCOUNT,
                                severity=Severity.MEDIUM,
                                title=f"Linked Accounts: {len(info['social_links'])}",
                                description="Social accounts mentioned in Reddit activity",
                                source="Reddit Analysis",
                                timestamp=datetime.utcnow(),
                                data={
                                    "links": info["social_links"],
                                },
                                parent_id=parent_id,
                                link_label="links to",
                            )

                    # Activity summary
                    yield Finding(
                        id=str(uuid.uuid4()),
                        type=NodeType.ACCOUNT,
                        severity=Severity.LOW,
                        title=f"Reddit Profile: {data.get('karma', 0)} karma",
                        description=f"Top subs: {', '.join(list(data.get('top_subreddits', {}).keys())[:5])}",
                        source="Reddit",
                        source_url=f"https://reddit.com/u/{username}",
                        timestamp=datetime.utcnow(),
                        data=data,
                        parent_id=parent_id,
                        link_label="profile",
                    )

            # Twitter deep scrape
            elif platform in ["twitter", "x"]:
                data = await self._scrape_twitter_nitter(client, username)

                if data:
                    if data.get("location"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location (Twitter): {data['location']}",
                            description="Location from Twitter profile",
                            source="Twitter via Nitter",
                            source_url=f"https://twitter.com/{username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "location": data["location"],
                                "confidence": "high",
                            },
                            parent_id=parent_id,
                            link_label="located in",
                        )

                    if data.get("bio"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.LOW,
                            title="Twitter Bio",
                            description=data["bio"][:200],
                            source="Twitter",
                            timestamp=datetime.utcnow(),
                            data={"bio": data["bio"]},
                            parent_id=parent_id,
                            link_label="bio",
                        )

                    if data.get("website"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Website: {data['website']}",
                            description="Website linked on Twitter",
                            source="Twitter",
                            source_url=data["website"],
                            timestamp=datetime.utcnow(),
                            data={"url": data["website"]},
                            parent_id=parent_id,
                            link_label="links to",
                        )

                    if data.get("extracted_info", {}).get("social_links"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Bio Links: {len(data['extracted_info']['social_links'])}",
                            description="Other accounts mentioned in Twitter bio",
                            source="Twitter Bio Analysis",
                            timestamp=datetime.utcnow(),
                            data={
                                "links": data["extracted_info"]["social_links"],
                            },
                            parent_id=parent_id,
                            link_label="links to",
                        )

            # GitHub deep scrape
            elif platform == "github":
                data = await self._scrape_github_deep(client, username)

                if data:
                    if data.get("name"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.HIGH,
                            title=f"Real Name: {data['name']}",
                            description="Name from GitHub profile",
                            source="GitHub",
                            source_url=f"https://github.com/{username}",
                            timestamp=datetime.utcnow(),
                            data={"name": data["name"]},
                            parent_id=parent_id,
                            link_label="real name",
                        )

                    if data.get("email"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.HIGH,
                            title=f"Public Email: {data['email']}",
                            description="Email publicly displayed on GitHub",
                            source="GitHub",
                            timestamp=datetime.utcnow(),
                            data={"email": data["email"]},
                            parent_id=parent_id,
                            link_label="email",
                        )

                    if data.get("company"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.HIGH,
                            title=f"Employer: {data['company']}",
                            description="Company from GitHub profile",
                            source="GitHub",
                            timestamp=datetime.utcnow(),
                            data={"company": data["company"]},
                            parent_id=parent_id,
                            link_label="works at",
                        )

                    if data.get("location"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location: {data['location']}",
                            description="Location from GitHub profile",
                            source="GitHub",
                            timestamp=datetime.utcnow(),
                            data={"location": data["location"]},
                            parent_id=parent_id,
                            link_label="located in",
                        )

                    if data.get("twitter"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Twitter: @{data['twitter']}",
                            description="Twitter linked on GitHub",
                            source="GitHub",
                            source_url=f"https://twitter.com/{data['twitter']}",
                            timestamp=datetime.utcnow(),
                            data={"twitter": data["twitter"]},
                            parent_id=parent_id,
                            link_label="links to",
                        )
