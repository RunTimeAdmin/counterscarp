from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote

from logger import get_logger
from http_utils import resilient_get, RateLimiter

logger = get_logger(__name__)

# Shared rate limiter for API calls in this module
# GitHub API: 10 requests per second is reasonable for unauthenticated
# RSS feeds: Can be more lenient
_rate_limiter = RateLimiter(requests_per_second=5)

# --- CONFIGURATION ---
# GitHub API for Code4rena
C4_API_URL = "https://api.github.com/search/issues"
C4_TIMEOUT = 10  # seconds

# Immunefi publishes reports on Medium. We use the RSS feed to fetch
# the latest "School of Rock" / Spotlights.
IMMUNEFI_RSS = "https://medium.com/feed/immunefi"
IMMUNEFI_TIMEOUT = 10  # seconds

# Solodit URL constructor
SOLODIT_BASE = "https://solodit.xyz/search"

def get_contract_context(filepath: str) -> List[str]:
    """Scans the file to determine specific tags (e.g., "ERC4626", "Oracle").

    Args:
        filepath: Path to the Solidity file to analyze.

    Returns:
        List of detected context tags.
    """
    tags = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            if "erc20" in content: tags.add("ERC20")
            if "erc721" in content or "nft" in content: tags.add("NFT")
            if "lending" in content or "collateral" in content: tags.add("Lending")
            if "staking" in content or "reward" in content: tags.add("Staking")
            if "vault" in content or "erc4626" in content: tags.add("ERC4626")
            if "oracle" in content or "chainlink" in content: tags.add("Oracle")
            if "swap" in content or "amm" in content: tags.add("AMM")
            if "bridge" in content: tags.add("Bridge")
            if "governance" in content or "voting" in content: tags.add("Governance")
            if "flash" in content: tags.add("FlashLoan")
            if "proxy" in content or "upgradeable" in content: tags.add("Upgradeable")
    except (IOError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Could not read contract file for context: {e}")
    except Exception as e:
        logger.error(f"Unexpected error scanning contract context: {e}")

    # Default to generic if nothing found
    if not tags:
        tags.add("Smart Contract")
    return list(tags)

# Backwards compatibility alias
scan_file_for_context = get_contract_context

# --- MODULE 1: CODE4RENA SCRAPER ---
def fetch_c4_findings(keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch Code4rena findings for given keywords.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Code4rena findings.
    """
    print(f"    [*] Querying Code4rena (GitHub)...")
    query = f"org:code-423n4 is:issue label:\"3 (High Risk)\" {' '.join(keywords)}"
    params = {"q": query, "sort": "created", "order": "desc", "per_page": 3}

    try:
        resp = resilient_get(
            C4_API_URL,
            params=params,
            timeout=C4_TIMEOUT,
            max_retries=3,
            rate_limiter=_rate_limiter
        )
        return resp.json().get("items", [])
    except Exception as e:
        logger.warning(f"Code4rena API request failed: {e}")
    return []

# Backwards compatibility alias
search_c4_findings = fetch_c4_findings

# --- MODULE 2: IMMUNEFI RSS PARSER ---
def fetch_immunefi_reports(keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch Immunefi reports for given keywords.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Immunefi report dictionaries.
    """
    print(f"    [*] Querying Immunefi (Medium RSS)...")
    reports = []
    try:
        resp = resilient_get(
            IMMUNEFI_RSS,
            timeout=IMMUNEFI_TIMEOUT,
            max_retries=3,
            rate_limiter=_rate_limiter
        )

        # Parse XML Feed
        root = ET.fromstring(resp.content)

        # Iterate channel items
        for item in root.findall("./channel/item"):
            title_elem = item.find("title")
            link_elem = item.find("link")

            if title_elem is None or link_elem is None:
                continue

            title = title_elem.text
            link = link_elem.text
            categories = [c.text.lower() for c in item.findall("category") if c.text]

            # Filter: We only want "Spotlights" or "Breakdowns", not generic PR news
            if any(k.lower() in title.lower() for k in keywords) or "vulnerability" in title.lower():
                reports.append({"title": title, "url": link, "source": "Immunefi"})

            # Limit to 3
            if len(reports) >= 3:
                break

    except ET.ParseError as e:
        logger.warning(f"Failed to parse Immunefi RSS XML: {e}")
    except Exception as e:
        logger.warning(f"Immunefi RSS request failed: {e}")

    return reports

# --- MODULE 3: SOLODIT DEEP LINKER ---
def generate_solodit_links(keywords: List[str]) -> List[Dict[str, str]]:
    """Generate Solodit deep links for given keywords.

    Since Solodit is hard to scrape (React), we generate precise Deep Links.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Solodit link dictionaries.
    """
    links = []
    for k in keywords:
        # Construct a query for High Severity + Keyword
        # Solodit query param format is usually ?q=KEYWORD
        query = quote(k)
        url = f"{SOLODIT_BASE}?q={query}&min_severity=HIGH"
        links.append({"title": f"Solodit Search: High Severity '{k}' Bugs", "url": url, "source": "Solodit"})
    return links

# --- REPORT GENERATOR ---
def generate_comprehensive_report(filepath: str) -> Dict[str, Any]:
    """Generate comprehensive threat intelligence report.

    Args:
        filepath: Path to the Solidity file to analyze.

    Returns:
        Dictionary with context, Code4rena, Immunefi, and Solodit data.
    """
    logger.info(f"Generating comprehensive report for: {filepath}")
    print("\n" + "="*70)
    print(f" 🧠 KNOWLEDGE ENGINE (C4 + Immunefi + Solodit)")
    print("="*70)
    
    # 1. Analyze Context
    tags = get_contract_context(filepath)
    print(f"[*] Detected Context: {', '.join(tags)}")
    print("-" * 70)

    # 2. Fetch Data
    c4_data = fetch_c4_findings(tags)
    immunefi_data = fetch_immunefi_reports(tags)
    solodit_data = generate_solodit_links(tags)

    # 3. Output Code4rena (Raw Findings)
    if c4_data:
        print(f"\n[CODE4RENA] Relevant High-Severity Findings:")
        for item in c4_data:
            print(f"  • {item['title']}")
            print(f"    Url: {item['html_url']}")
    else:
        print("\n[CODE4RENA] No direct matches found recently.")

    # 4. Output Immunefi (Major Hacks)
    if immunefi_data:
        print(f"\n[IMMUNEFI] Related Post-Mortems:")
        for item in immunefi_data:
            print(f"  • {item['title']}")
            print(f"    Url: {item['url']}")
    else:
        print("\n[IMMUNEFI] No recent RSS matches (Check DeFiHackLabs manually).")

    # 5. Output Solodit (Deep Links)
    if solodit_data:
        print(f"\n[SOLODIT] Manual Research Links (Deep Search):")
        for item in solodit_data:
            print(f"  • {item['title']}")
            print(f"    Url: {item['url']}")

    print("\n" + "="*70)
    
    # Return all data for programmatic use (GUI integration)
    return {
        "context": tags,
        "code4rena": c4_data,
        "immunefi": immunefi_data,
        "solodit": solodit_data
    }

# Backwards compatibility wrapper
def generate_reference_report(filepath):
    """Legacy function name for GUI compatibility"""
    return generate_comprehensive_report(filepath)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Multi-Source Knowledge Fetcher"
    )
    parser.add_argument(
        "file",
        help="The solidity file to analyze context for"
    )
    args = parser.parse_args()

    try:
        generate_comprehensive_report(args.file)
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise
