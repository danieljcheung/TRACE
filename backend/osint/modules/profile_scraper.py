"""
Deep profile scraper - extracts detailed data from found accounts.
Analyzes Reddit activity, Twitter bios, and other profile data.
"""

import httpx
import uuid
import re
from typing import AsyncGenerator
from datetime import datetime
from collections import Counter

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


# Location subreddits for inference
LOCATION_SUBREDDITS = {
    # US Cities
    "nyc": "New York City",
    "newyorkcity": "New York City",
    "manhattan": "New York City",
    "brooklyn": "Brooklyn, NY",
    "losangeles": "Los Angeles",
    "sanfrancisco": "San Francisco",
    "bayarea": "San Francisco Bay Area",
    "seattle": "Seattle",
    "chicago": "Chicago",
    "boston": "Boston",
    "austin": "Austin",
    "denver": "Denver",
    "portland": "Portland",
    "philadelphia": "Philadelphia",
    "atlanta": "Atlanta",
    "miami": "Miami",
    "dallas": "Dallas",
    "houston": "Houston",
    "phoenix": "Phoenix",
    "sandiego": "San Diego",
    "washingtondc": "Washington DC",
    "dc": "Washington DC",
    # International
    "london": "London, UK",
    "unitedkingdom": "United Kingdom",
    "toronto": "Toronto",
    "vancouver": "Vancouver",
    "canada": "Canada",
    "australia": "Australia",
    "sydney": "Sydney",
    "melbourne": "Melbourne",
    "berlin": "Berlin",
    "germany": "Germany",
    "paris": "Paris",
    "france": "France",
    "amsterdam": "Amsterdam",
    "netherlands": "Netherlands",
    "india": "India",
    "bangalore": "Bangalore, India",
    "mumbai": "Mumbai, India",
    "delhi": "Delhi, India",
    "singapore": "Singapore",
    "japan": "Japan",
    "tokyo": "Tokyo",
    # States/Regions
    "california": "California",
    "texas": "Texas",
    "florida": "Florida",
    "newjersey": "New Jersey",
    "newengland": "New England",
}


class ProfileScraper(OSINTModule):
    name = "Profile Deep Scraper"
    description = "Extract detailed information from found profiles"

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html",
        }

    async def _scrape_reddit(self, client: httpx.AsyncClient, username: str) -> list[dict]:
        """Scrape Reddit profile for location hints and personal info."""
        findings_data = []

        try:
            # Get user about
            resp = await client.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "TRACE-OSINT/1.0"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {})

                # Account age and karma
                created = data.get("created_utc")
                karma = data.get("total_karma", 0)

                findings_data.append({
                    "type": "profile_stats",
                    "karma": karma,
                    "created": created,
                })

            # Get recent posts/comments for subreddit analysis
            resp = await client.get(
                f"https://www.reddit.com/user/{username}/comments.json",
                params={"limit": 100},
                headers={"User-Agent": "TRACE-OSINT/1.0"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                posts = resp.json().get("data", {}).get("children", [])
                subreddits = Counter()

                for post in posts:
                    sub = post.get("data", {}).get("subreddit", "").lower()
                    if sub:
                        subreddits[sub] += 1

                # Check for location subreddits
                location_hints = []
                for sub, count in subreddits.most_common(20):
                    if sub in LOCATION_SUBREDDITS:
                        location_hints.append({
                            "subreddit": sub,
                            "location": LOCATION_SUBREDDITS[sub],
                            "posts": count,
                        })

                if location_hints:
                    findings_data.append({
                        "type": "location_hints",
                        "hints": location_hints,
                        "top_subreddits": subreddits.most_common(10),
                    })

        except Exception as e:
            print(f"[ProfileScraper] Reddit error: {e}")

        return findings_data

    async def _scrape_twitter_nitter(self, client: httpx.AsyncClient, username: str) -> dict | None:
        """Scrape Twitter profile via Nitter instances."""
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

                    # Extract bio
                    bio_match = re.search(r'<p class="profile-bio"[^>]*>(.*?)</p>', html, re.DOTALL)
                    bio = bio_match.group(1).strip() if bio_match else None

                    # Extract location
                    loc_match = re.search(r'<span class="profile-location"[^>]*>(.*?)</span>', html, re.DOTALL)
                    location = loc_match.group(1).strip() if loc_match else None

                    # Extract website
                    web_match = re.search(r'<a class="profile-website"[^>]*href="([^"]+)"', html)
                    website = web_match.group(1) if web_match else None

                    # Extract follower count
                    followers_match = re.search(r'<span class="profile-stat-num"[^>]*>([0-9,]+)</span>\s*<span[^>]*>Followers', html)
                    followers = followers_match.group(1).replace(",", "") if followers_match else None

                    if any([bio, location, website]):
                        return {
                            "bio": bio,
                            "location": location,
                            "website": website,
                            "followers": int(followers) if followers else None,
                            "source_instance": instance,
                        }

            except Exception:
                continue

        return None

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Deep scrape a profile.

        Seed format: "platform:username" (e.g., "reddit:johndoe")
        """

        if ':' not in seed:
            return

        platform, username = seed.split(':', 1)
        platform = platform.lower().strip()
        username = username.strip()

        if not username:
            return

        async with httpx.AsyncClient(headers=self.headers, follow_redirects=True) as client:

            # Reddit deep scrape
            if platform == "reddit":
                reddit_data = await self._scrape_reddit(client, username)

                for item in reddit_data:
                    if item["type"] == "location_hints" and item.get("hints"):
                        # Find most likely location
                        top_hint = max(item["hints"], key=lambda x: x["posts"])

                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location (Reddit): {top_hint['location']}",
                            description=f"Inferred from r/{top_hint['subreddit']} activity ({top_hint['posts']} posts)",
                            source="Reddit Activity Analysis",
                            source_url=f"https://reddit.com/u/{username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "location": top_hint["location"],
                                "source": "subreddit_activity",
                                "subreddit": top_hint["subreddit"],
                                "confidence": "medium" if top_hint["posts"] > 5 else "low",
                                "all_hints": item["hints"],
                            },
                            parent_id=parent_id,
                            link_label="likely in",
                        )

                        # Report all location hints if multiple
                        if len(item["hints"]) > 1:
                            all_locations = ", ".join(h["location"] for h in item["hints"][:3])
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.PERSONAL_INFO,
                                severity=Severity.LOW,
                                title=f"Location Interests: {all_locations}",
                                description="Multiple location-based subreddit activity detected",
                                source="Reddit Analysis",
                                timestamp=datetime.utcnow(),
                                data={"locations": item["hints"]},
                                parent_id=parent_id,
                                link_label="interested in",
                            )

            # Twitter deep scrape via Nitter
            elif platform in ["twitter", "x"]:
                twitter_data = await self._scrape_twitter_nitter(client, username)

                if twitter_data:
                    if twitter_data.get("location"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.MEDIUM,
                            title=f"Location (Twitter): {twitter_data['location']}",
                            description="Location from Twitter profile",
                            source="Twitter (via Nitter)",
                            source_url=f"https://twitter.com/{username}",
                            timestamp=datetime.utcnow(),
                            data={
                                "location": twitter_data["location"],
                                "source": "twitter_profile",
                                "confidence": "high",
                            },
                            parent_id=parent_id,
                            link_label="located in",
                        )

                    if twitter_data.get("bio"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.PERSONAL_INFO,
                            severity=Severity.LOW,
                            title="Twitter Bio",
                            description=twitter_data["bio"][:200],
                            source="Twitter",
                            source_url=f"https://twitter.com/{username}",
                            timestamp=datetime.utcnow(),
                            data={"bio": twitter_data["bio"]},
                            parent_id=parent_id,
                            link_label="bio",
                        )

                    if twitter_data.get("website"):
                        yield Finding(
                            id=str(uuid.uuid4()),
                            type=NodeType.ACCOUNT,
                            severity=Severity.MEDIUM,
                            title=f"Website: {twitter_data['website']}",
                            description="Website linked on Twitter profile",
                            source="Twitter",
                            source_url=twitter_data["website"],
                            timestamp=datetime.utcnow(),
                            data={"url": twitter_data["website"]},
                            parent_id=parent_id,
                            link_label="links to",
                        )
