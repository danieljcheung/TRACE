"""Risk score calculation."""

from models.findings import Finding, Severity


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    """
    Calculate overall risk score from findings.

    Scoring:
    - Critical: 25 pts each (max 50)
    - High: 10 pts each (max 30)
    - Medium: 3 pts each (max 15)
    - Low: 1 pt each (max 5)

    Bonus penalties:
    - Password exposed: +15
    - Home address found: +15
    - Phone number found: +10
    - Name + Location combo: +5
    - 10+ accounts: +5

    Returns:
        Tuple of (score 0-100, risk_level string)
    """
    score = 0

    # Count by severity
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL or f.severity == 'critical')
    high = sum(1 for f in findings if f.severity == Severity.HIGH or f.severity == 'high')
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM or f.severity == 'medium')
    low = sum(1 for f in findings if f.severity == Severity.LOW or f.severity == 'low')

    # Base scoring with caps
    score += min(critical * 25, 50)
    score += min(high * 10, 30)
    score += min(medium * 3, 15)
    score += min(low * 1, 5)

    # Check for high-risk indicators
    titles_lower = [f.title.lower() for f in findings]
    descriptions_lower = [f.description.lower() for f in findings]
    all_text = ' '.join(titles_lower + descriptions_lower)

    # Password exposed
    if 'password' in all_text and ('exposed' in all_text or 'breach' in all_text):
        score += 15

    # Address found
    if 'address' in all_text and any(s in all_text for s in ['home', 'street', 'residence']):
        score += 15

    # Phone number
    if 'phone' in all_text:
        score += 10

    # Name + Location combo
    has_name = any('name' in t and ':' in t for t in titles_lower)
    has_location = any('location' in t for t in titles_lower)
    if has_name and has_location:
        score += 5

    # Many accounts
    account_count = sum(1 for f in findings if f.type == 'account' or str(f.type) == 'account')
    if account_count > 10:
        score += 5

    # Cap at 100
    score = min(score, 100)

    # Determine level
    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def get_risk_bar(score: int, width: int = 30) -> str:
    """Generate ASCII risk bar."""
    filled = int((score / 100) * width)
    empty = width - filled

    if score >= 70:
        char = '#'
    elif score >= 50:
        char = '='
    elif score >= 30:
        char = '-'
    else:
        char = '.'

    return f"[{char * filled}{'-' * empty}] {score}/100"
