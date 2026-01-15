"""
Data broker warning module.
Generates search URLs for major people-search sites and provides opt-out information.
"""

import uuid
import urllib.parse
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


# Major data brokers with search URL templates and opt-out links
DATA_BROKERS = [
    {
        "name": "Spokeo",
        "search_url": "https://www.spokeo.com/search?q={email}",
        "opt_out": "https://www.spokeo.com/optout",
        "data_types": ["name", "address", "phone", "email", "social profiles"],
        "severity": "high",
    },
    {
        "name": "BeenVerified",
        "search_url": "https://www.beenverified.com/f/search?email={email}",
        "opt_out": "https://www.beenverified.com/app/optout/search",
        "data_types": ["name", "address", "phone", "relatives", "criminal records"],
        "severity": "high",
    },
    {
        "name": "WhitePages",
        "search_url": "https://www.whitepages.com/search?q={email}",
        "opt_out": "https://www.whitepages.com/suppression-requests",
        "data_types": ["name", "address", "phone", "relatives"],
        "severity": "high",
    },
    {
        "name": "TruePeopleSearch",
        "search_url": "https://www.truepeoplesearch.com/results?email={email}",
        "opt_out": "https://www.truepeoplesearch.com/removal",
        "data_types": ["name", "address", "phone", "associates"],
        "severity": "high",
    },
    {
        "name": "FastPeopleSearch",
        "search_url": "https://www.fastpeoplesearch.com/search?q={email}",
        "opt_out": "https://www.fastpeoplesearch.com/removal",
        "data_types": ["name", "address", "phone"],
        "severity": "medium",
    },
    {
        "name": "Intelius",
        "search_url": "https://www.intelius.com/search?q={email}",
        "opt_out": "https://www.intelius.com/opt-out",
        "data_types": ["name", "address", "phone", "criminal records", "court records"],
        "severity": "high",
    },
    {
        "name": "PeopleFinder",
        "search_url": "https://www.peoplefinder.com/search?q={email}",
        "opt_out": "https://www.peoplefinder.com/optout",
        "data_types": ["name", "address", "phone", "relatives"],
        "severity": "medium",
    },
    {
        "name": "Radaris",
        "search_url": "https://radaris.com/search?email={email}",
        "opt_out": "https://radaris.com/page/how-to-remove",
        "data_types": ["name", "address", "phone", "property records", "social profiles"],
        "severity": "high",
    },
    {
        "name": "USSearch",
        "search_url": "https://www.ussearch.com/search?q={email}",
        "opt_out": "https://www.ussearch.com/opt-out",
        "data_types": ["name", "address", "phone", "criminal records"],
        "severity": "medium",
    },
    {
        "name": "ThatsThem",
        "search_url": "https://thatsthem.com/email/{email}",
        "opt_out": "https://thatsthem.com/optout",
        "data_types": ["name", "address", "phone", "email"],
        "severity": "medium",
    },
    {
        "name": "Pipl",
        "search_url": "https://pipl.com/search/?q={email}",
        "opt_out": "https://pipl.com/personal-information-removal-request",
        "data_types": ["name", "address", "email", "social profiles", "photos"],
        "severity": "high",
    },
    {
        "name": "PeekYou",
        "search_url": "https://www.peekyou.com/search?q={email}",
        "opt_out": "https://www.peekyou.com/about/contact/optout",
        "data_types": ["name", "social profiles", "photos", "web presence"],
        "severity": "medium",
    },
]


class DataBrokerCheck(OSINTModule):
    name = "Data Broker Warning"
    description = "Check for exposure on people-search sites"

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """
        Generate data broker warnings and search URLs.

        Note: Does not actually scrape these sites (they block automated access).
        Instead, provides search URLs and opt-out instructions.
        """

        email = seed.lower().strip()
        if '@' not in email:
            return

        # URL encode the email
        encoded_email = urllib.parse.quote(email)

        # Get name from email if possible (for name-based searches)
        local = email.split('@')[0]
        name_parts = local.replace('.', ' ').replace('_', ' ').replace('-', ' ').split()

        # Main warning finding
        yield Finding(
            id=str(uuid.uuid4()),
            type=NodeType.BREACH,
            severity=Severity.HIGH,
            title="Data Broker Exposure Warning",
            description=f"Your information is likely listed on {len(DATA_BROKERS)} people-search sites",
            source="Data Broker Analysis",
            timestamp=datetime.utcnow(),
            data={
                "broker_count": len(DATA_BROKERS),
                "warning": "These sites aggregate public records and may expose your personal information",
                "recommendation": "Consider opting out from each site",
            },
            parent_id=parent_id,
            link_label="exposed on",
        )

        # Generate findings for each broker
        high_risk = []
        medium_risk = []

        for broker in DATA_BROKERS:
            search_url = broker["search_url"].format(email=encoded_email)

            broker_info = {
                "name": broker["name"],
                "search_url": search_url,
                "opt_out_url": broker["opt_out"],
                "data_types": broker["data_types"],
            }

            if broker["severity"] == "high":
                high_risk.append(broker_info)
            else:
                medium_risk.append(broker_info)

        # High-risk brokers finding
        if high_risk:
            yield Finding(
                id=str(uuid.uuid4()),
                type=NodeType.BREACH,
                severity=Severity.HIGH,
                title=f"High-Risk Brokers: {len(high_risk)} sites",
                description="Sites with extensive personal data collection",
                source="Data Broker Analysis",
                timestamp=datetime.utcnow(),
                data={
                    "brokers": high_risk,
                    "risk_level": "high",
                    "action_required": "Opt-out recommended",
                },
                parent_id=parent_id,
                link_label="exposed on",
            )

        # Medium-risk brokers finding
        if medium_risk:
            yield Finding(
                id=str(uuid.uuid4()),
                type=NodeType.BREACH,
                severity=Severity.MEDIUM,
                title=f"Other Brokers: {len(medium_risk)} sites",
                description="Additional people-search sites",
                source="Data Broker Analysis",
                timestamp=datetime.utcnow(),
                data={
                    "brokers": medium_risk,
                    "risk_level": "medium",
                },
                parent_id=parent_id,
                link_label="listed on",
            )

        # Opt-out summary
        all_opt_outs = [
            {"name": b["name"], "url": b["opt_out"]}
            for b in DATA_BROKERS
        ]

        yield Finding(
            id=str(uuid.uuid4()),
            type=NodeType.PERSONAL_INFO,
            severity=Severity.LOW,
            title="Opt-Out Links Available",
            description=f"Direct removal links for {len(all_opt_outs)} data brokers",
            source="Data Broker Analysis",
            timestamp=datetime.utcnow(),
            data={
                "opt_out_links": all_opt_outs,
                "instructions": "Visit each link to request removal of your data",
                "note": "Removal may take 30-60 days per site",
            },
            parent_id=parent_id,
            link_label="remove from",
        )
