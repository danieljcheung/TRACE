"""Data models for OSINT findings."""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class NodeType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    ACCOUNT = "account"
    PERSONAL_INFO = "personal_info"
    BREACH = "breach"
    DOMAIN = "domain"


class Finding(BaseModel):
    """A single OSINT finding / graph node."""
    id: str
    type: NodeType
    severity: Severity
    title: str
    description: str
    source: str
    source_url: Optional[str] = None
    timestamp: datetime
    data: dict = {}
    parent_id: Optional[str] = None
    link_label: Optional[str] = None

    class Config:
        use_enum_values = True
