"""
Google Dorking module - searches for documents and pages containing the email.
Uses DuckDuckGo as a proxy (Google blocks automated searches).
"""

import httpx
import uuid
import re
import urllib.parse
from typing import AsyncGenerator
from datetime import datetime

from .base import OSINTModule
from models.findings import Finding, NodeType, Severity


class GoogleDork(OSINTModule):
    name = "Document Search"
    description = "Search for documents and pages containing email"

    # DuckDuckGo HTML search (more permissive than Google)
    SEARCH_URL = "https://html.duckduckgo.com/html/"

    # Dork patterns to search
    DORK_PATTERNS = [
        # Documents
        ('"{email}" filetype:pdf', "PDF Documents", Severity.HIGH),
        ('"{email}" filetype:doc OR filetype:docx', "Word Documents", Severity.HIGH),
        ('"{email}" filetype:xls OR filetype:xlsx', "Spreadsheets", Severity.HIGH),
        ('"{email}" filetype:txt', "Text Files", Severity.MEDIUM),

        # Resume/CV searches
        ('"{email}" resume OR cv', "Resumes/CVs", Severity.HIGH),
        ('"{email}" inurl:resume', "Resume Pages", Severity.HIGH),

        # Paste sites
        ('"{email}" site:pastebin.com', "Pastebin", Severity.CRITICAL),
        ('"{email}" site:ghostbin.com OR site:rentry.co', "Paste Sites", Severity.CRITICAL),

        # Professional
        ('"{email}" site:linkedin.com', "LinkedIn", Severity.MEDIUM),
        ('"{email}" site:github.com', "GitHub", Severity.MEDIUM),

        # Forums and lists
        ('"{email}" site:reddit.com', "Reddit", Severity.LOW),
        ('"{email}" mailing list OR newsletter', "Mailing Lists", Severity.LOW),

        # Data dumps
        ('"{email}" dump OR leak OR breach', "Data Dumps", Severity.CRITICAL),
        ('"{email}" database OR sql', "Database References", Severity.HIGH),
    ]

    def __init__(self):
        self.timeout = 15.0
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        }

    async def _search_duckduckgo(
        self,
        client: httpx.AsyncClient,
        query: str
    ) -> list[dict]:
        """Search DuckDuckGo and extract results."""
        results = []

        try:
            resp = await client.post(
                self.SEARCH_URL,
                data={"q": query, "b": ""},
                headers=self.headers,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                html = resp.text

                # Extract result links and titles
                # DuckDuckGo HTML results have class="result__a"
                link_pattern = r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>'
                matches = re.findall(link_pattern, html, re.IGNORECASE)

                for url, title in matches[:10]:  # Limit to top 10
                    # Clean up URL (DuckDuckGo wraps URLs)
                    if "uddg=" in url:
                        url_match = re.search(r'uddg=([^&]+)', url)
                        if url_match:
                            url = urllib.parse.unquote(url_match.group(1))

                    results.append({
                        "url": url,
                        "title": title.strip(),
                    })

                # Also try snippet pattern
                snippet_pattern = r'<a[^>]*class="result__snippet"[^>]*>([^<]+)</a>'
                snippets = re.findall(snippet_pattern, html, re.IGNORECASE)

                for i, snippet in enumerate(snippets[:len(results)]):
                    if i < len(results):
                        results[i]["snippet"] = snippet.strip()

        except Exception as e:
            print(f"[GoogleDork] Search error: {e}")

        return results

    async def run(
        self,
        seed: str,
        depth: int,
        parent_id: str | None = None
    ) -> AsyncGenerator[Finding, None]:
        """Search for documents and pages containing the email."""

        email = seed.lower().strip()
        if '@' not in email:
            return

        async with httpx.AsyncClient() as client:
            all_results = []
            categories_found = set()

            for pattern, category, severity in self.DORK_PATTERNS:
                query = pattern.format(email=email)

                results = await self._search_duckduckgo(client, query)

                if results:
                    categories_found.add(category)

                    for result in results:
                        # Check if we've seen this URL
                        if any(r["url"] == result["url"] for r in all_results):
                            continue

                        all_results.append({
                            **result,
                            "category": category,
                            "severity": severity,
                            "query": query,
                        })

                        # Yield individual findings for high-severity results
                        if severity in [Severity.CRITICAL, Severity.HIGH]:
                            yield Finding(
                                id=str(uuid.uuid4()),
                                type=NodeType.PERSONAL_INFO,
                                severity=severity,
                                title=f"{category}: {result['title'][:50]}",
                                description=result.get("snippet", "Document found via search")[:200],
                                source="Document Search",
                                source_url=result["url"],
                                timestamp=datetime.utcnow(),
                                data={
                                    "url": result["url"],
                                    "title": result["title"],
                                    "category": category,
                                    "search_query": query,
                                    "remediation": self._get_remediation(category),
                                },
                                parent_id=parent_id,
                                link_label="found in",
                            )

                # Rate limiting between searches
                import asyncio
                await asyncio.sleep(1.5)

            # Summary finding
            if all_results:
                yield Finding(
                    id=str(uuid.uuid4()),
                    type=NodeType.PERSONAL_INFO,
                    severity=Severity.HIGH,
                    title=f"Found in {len(all_results)} Search Results",
                    description=f"Categories: {', '.join(categories_found)}",
                    source="Document Search",
                    timestamp=datetime.utcnow(),
                    data={
                        "total_results": len(all_results),
                        "categories": list(categories_found),
                        "results": all_results[:20],  # Limit stored results
                    },
                    parent_id=parent_id,
                    link_label="indexed in",
                )

    def _get_remediation(self, category: str) -> str:
        """Get remediation advice for each category."""
        remediation = {
            "PDF Documents": "Request removal from hosting site or search engine",
            "Word Documents": "Contact site owner to remove document",
            "Spreadsheets": "Request removal; may contain sensitive data",
            "Resumes/CVs": "Remove from job sites; request delisting",
            "Resume Pages": "Update privacy settings or delete old profiles",
            "Pastebin": "Report to Pastebin for removal if contains PII",
            "Paste Sites": "Report for removal; may contain leaked data",
            "LinkedIn": "Review LinkedIn privacy settings",
            "GitHub": "Check for accidental commits of personal info",
            "Reddit": "Delete old posts containing email",
            "Mailing Lists": "Unsubscribe and request archive removal",
            "Data Dumps": "CRITICAL: Check for leaked credentials; change passwords",
            "Database References": "May indicate breach; monitor accounts",
        }
        return remediation.get(category, "Review and request removal if necessary")
