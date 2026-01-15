"""
Location inference module - aggregates location hints from all sources.
Provides confidence-scored location estimates.
"""

import uuid
from typing import AsyncGenerator
from datetime import datetime
from collections import defaultdict

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class LocationInference(OSINTModule):
    name = "Location Inference"
    description = "Aggregate and analyze location data from all sources"

    # Confidence weights by source type
    SOURCE_WEIGHTS = {
        "github_profile": 0.9,
        "twitter_profile": 0.85,
        "linkedin_profile": 0.95,
        "gravatar_profile": 0.7,
        "subreddit_activity": 0.6,
        "timezone_inference": 0.5,
        "domain_registration": 0.4,
        "commit_timezone": 0.55,
        "ip_geolocation": 0.3,
    }

    def _normalize_location(self, location: str) -> str:
        """Normalize location string for comparison."""
        location = location.lower().strip()

        # Common abbreviations
        replacements = {
            "sf": "san francisco",
            "nyc": "new york city",
            "la": "los angeles",
            "dc": "washington dc",
            "uk": "united kingdom",
            "usa": "united states",
            "us": "united states",
        }

        for abbr, full in replacements.items():
            if location == abbr or location.endswith(f", {abbr}"):
                location = location.replace(abbr, full)

        return location

    def _extract_city_region(self, location: str) -> tuple[str | None, str | None]:
        """Extract city and region from location string."""
        parts = [p.strip() for p in location.split(",")]

        if len(parts) >= 2:
            return parts[0], parts[1]
        elif len(parts) == 1:
            return parts[0], None
        return None, None

    def _calculate_confidence(self, sources: list[dict]) -> float:
        """Calculate overall confidence from multiple sources."""
        if not sources:
            return 0.0

        total_weight = 0
        weighted_sum = 0

        for source in sources:
            source_type = source.get("source_type", "unknown")
            weight = self.SOURCE_WEIGHTS.get(source_type, 0.3)
            source_confidence = source.get("confidence_score", 0.5)

            weighted_sum += weight * source_confidence
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return min(weighted_sum / total_weight, 1.0)

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Analyze aggregated location data.

        Seed format: JSON string of location hints from other modules.
        Expected structure: [{"location": "...", "source": "...", "confidence": ...}, ...]
        """
        import json

        try:
            location_hints = json.loads(seed) if isinstance(seed, str) else seed
        except (json.JSONDecodeError, TypeError):
            return

        if not location_hints or not isinstance(location_hints, list):
            return

        # Group locations by normalized form
        location_groups = defaultdict(list)

        for hint in location_hints:
            loc = hint.get("location", "")
            if not loc:
                continue

            normalized = self._normalize_location(loc)
            city, region = self._extract_city_region(normalized)

            location_groups[normalized].append({
                "original": loc,
                "source": hint.get("source", "unknown"),
                "source_type": hint.get("source_type", "unknown"),
                "confidence_score": hint.get("confidence", 0.5),
            })

            # Also group by city alone for partial matches
            if city:
                location_groups[city].append({
                    "original": loc,
                    "source": hint.get("source", "unknown"),
                    "source_type": hint.get("source_type", "unknown"),
                    "confidence_score": hint.get("confidence", 0.5) * 0.8,  # Slightly lower for partial
                })

        if not location_groups:
            return

        # Find the most supported location
        best_location = None
        best_sources = []
        best_score = 0

        for loc, sources in location_groups.items():
            # Score based on number of sources and their confidence
            confidence = self._calculate_confidence(sources)
            source_count_bonus = min(len(sources) * 0.1, 0.3)  # Up to 0.3 bonus for multiple sources
            total_score = confidence + source_count_bonus

            if total_score > best_score:
                best_score = total_score
                best_location = loc
                best_sources = sources

        if not best_location or best_score < 0.3:
            return

        # Determine confidence level
        if best_score >= 0.8:
            confidence_level = "high"
            severity = Severity.HIGH
        elif best_score >= 0.5:
            confidence_level = "medium"
            severity = Severity.MEDIUM
        else:
            confidence_level = "low"
            severity = Severity.LOW

        # Get the best original representation
        original_location = best_sources[0]["original"] if best_sources else best_location

        yield Finding(
            id=str(uuid.uuid4()),
            type=NodeType.PERSONAL_INFO,
            severity=severity,
            title=f"Probable Location: {original_location.title()}",
            description=f"Location inferred from {len(best_sources)} source(s) with {confidence_level} confidence",
            source="Location Analysis",
            timestamp=datetime.utcnow(),
            data={
                "location": original_location,
                "normalized": best_location,
                "confidence": round(best_score, 2),
                "confidence_level": confidence_level,
                "sources": [s["source"] for s in best_sources],
                "source_count": len(best_sources),
            },
            parent_id=parent_id,
            link_label="probably in",
        )

        # If we have multiple strong candidates, report uncertainty
        strong_candidates = [
            (loc, sources) for loc, sources in location_groups.items()
            if len(sources) >= 2 and loc != best_location
        ]

        if strong_candidates:
            alternatives = [loc.title() for loc, _ in strong_candidates[:3]]
            yield Finding(
                id=str(uuid.uuid4()),
                type=NodeType.PERSONAL_INFO,
                severity=Severity.LOW,
                title=f"Alternative Locations: {', '.join(alternatives)}",
                description="Other possible locations based on activity",
                source="Location Analysis",
                timestamp=datetime.utcnow(),
                data={
                    "alternatives": alternatives,
                    "primary_location": original_location,
                },
                parent_id=parent_id,
                link_label="possibly in",
            )
