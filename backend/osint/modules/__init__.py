"""OSINT modules registry - Aggressive Deep Scan with Username Discovery."""

from .base import OSINTModule

# Core modules
from .username_extractor import UsernameExtractor
from .username_checker import UsernameChecker
from .breach_lookup import BreachLookup
from .gravatar import GravatarLookup
from .github import GitHubLookup
from .whois_lookup import WhoisLookup
from .pgp_keys import PGPKeysLookup

# Deep scan modules
from .email_checker import EmailChecker
from .profile_scraper import ProfileScraper
from .connected_accounts import ConnectedAccountFinder
from .location_inference import LocationInference
from .data_broker_check import DataBrokerCheck

# Aggressive modules
from .google_dork import GoogleDork
from .paste_search import PasteSearch
from .reverse_lookup import ReverseLookup
from .wayback import WaybackLookup
from .github_secrets import GitHubSecrets
from .epieos import EpieosLookup
from .social_deep import SocialDeepDive

# Username discovery modules (find REAL usernames from email)
from .github_email_search import GitHubEmailSearch
from .keybase import KeybaseLookup
from .intelx import IntelXSearch
from .hudsonrock import HudsonRockSearch

# Aliases
Gravatar = GravatarLookup
PGPKeys = PGPKeysLookup

# HOP 1: Direct Email Intelligence + Username Discovery
HOP1_MODULES = [
    # Direct email analysis
    BreachLookup,        # XposedOrNot breaches
    EpieosLookup,        # Google account, service checks
    ReverseLookup,       # EmailRep, ThatsThem
    GoogleDork,          # Document/paste search
    PasteSearch,         # Paste/leak site search
    GravatarLookup,      # Gravatar profile + username extraction
    UsernameExtractor,   # Extract username patterns from email

    # Username discovery (finds REAL usernames, not just email prefix)
    GitHubEmailSearch,   # Find GitHub users by commit email
    KeybaseLookup,       # Keybase verified proofs (Twitter, GitHub, Reddit)
    IntelXSearch,        # IntelX leaked database search
    HudsonRockSearch,    # Stealer malware log search
]

# HOP 2: Username Expansion
HOP2_MODULES = [
    UsernameChecker,     # Platform account check
    GitHubLookup,        # GitHub deep scan
    GitHubSecrets,       # GitHub secrets scanner
    SocialDeepDive,      # Reddit/Twitter deep dive
    WaybackLookup,       # Archive.org search
    ProfileScraper,      # Legacy profile scraper
]

# HOP 3: Aggregation & Correlation
HOP3_MODULES = [
    DataBrokerCheck,     # Data broker warnings
    LocationInference,   # Location aggregation
    ConnectedAccountFinder,  # Cross-platform correlation
]

# Legacy compatibility
EMAIL_MODULES = HOP1_MODULES
USERNAME_MODULES = HOP2_MODULES
CORRELATION_MODULES = HOP3_MODULES
ALL_MODULES = HOP1_MODULES

__all__ = [
    "OSINTModule",
    # Module lists
    "HOP1_MODULES",
    "HOP2_MODULES",
    "HOP3_MODULES",
    "EMAIL_MODULES",
    "USERNAME_MODULES",
    "CORRELATION_MODULES",
    "ALL_MODULES",
    # Core modules
    "UsernameExtractor",
    "UsernameChecker",
    "BreachLookup",
    "GravatarLookup",
    "Gravatar",
    "GitHubLookup",
    "WhoisLookup",
    "PGPKeysLookup",
    "PGPKeys",
    # Deep scan modules
    "EmailChecker",
    "ProfileScraper",
    "ConnectedAccountFinder",
    "LocationInference",
    "DataBrokerCheck",
    # Aggressive modules
    "GoogleDork",
    "PasteSearch",
    "ReverseLookup",
    "WaybackLookup",
    "GitHubSecrets",
    "EpieosLookup",
    "SocialDeepDive",
    # Username discovery modules
    "GitHubEmailSearch",
    "KeybaseLookup",
    "IntelXSearch",
    "HudsonRockSearch",
]
