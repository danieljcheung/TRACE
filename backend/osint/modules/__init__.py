"""OSINT modules registry."""

from .base import OSINTModule
from .username_extractor import UsernameExtractor
from .username_checker import UsernameChecker
from .breach_lookup import BreachLookup
from .gravatar import GravatarLookup
from .github import GitHubLookup
from .whois_lookup import WhoisLookup
from .pgp_keys import PGPKeysLookup

# All available modules
ALL_MODULES = [
    UsernameExtractor,
    BreachLookup,
    GravatarLookup,
    WhoisLookup,
    PGPKeysLookup,
    # These run on usernames, not email directly
    # UsernameChecker,
    # GitHubLookup,
]

# Modules that run on discovered usernames
USERNAME_MODULES = [
    UsernameChecker,
    GitHubLookup,
]

__all__ = [
    "OSINTModule",
    "ALL_MODULES",
    "USERNAME_MODULES",
    "UsernameExtractor",
    "UsernameChecker",
    "BreachLookup",
    "GravatarLookup",
    "GitHubLookup",
    "WhoisLookup",
    "PGPKeysLookup",
]
