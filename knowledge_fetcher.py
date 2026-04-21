from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from urllib.parse import quote

from logger import get_logger
from http_utils import resilient_get, RateLimiter

# Import config loader
try:
    from config_loader import load_config, GarrisonConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None
_rate_limiter = None


def get_config() -> GarrisonConfig:
    """Get or load the configuration."""
    global _config
    if _config is None:
        if CONFIG_AVAILABLE:
            try:
                _config = load_config()
            except Exception:
                _config = GarrisonConfig()
        else:
            _config = GarrisonConfig()
    return _config


def get_rate_limiter() -> RateLimiter:
    """Get or create the rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        try:
            rate_limit = get_config().threat_intel.api_rate_limit
        except Exception:
            rate_limit = 5
        _rate_limiter = RateLimiter(requests_per_second=rate_limit)
    return _rate_limiter


def get_c4_timeout() -> int:
    """Get Code4rena API timeout from config or use default."""
    try:
        return get_config().threat_intel.c4_timeout
    except Exception:
        return 10


def get_immunefi_timeout() -> int:
    """Get Immunefi RSS timeout from config or use default."""
    try:
        return get_config().threat_intel.immunefi_timeout
    except Exception:
        return 10


# --- CONFIGURATION ---
# GitHub API for Code4rena
C4_API_URL = "https://api.github.com/search/issues"

# Immunefi publishes reports on Medium. We use the RSS feed to fetch
# the latest "School of Rock" / Spotlights.
IMMUNEFI_RSS = "https://medium.com/feed/immunefi"

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

def _filter_bundled_db(query: str, source: str = None) -> List[Dict[str, Any]]:
    """Filter bundled threat intel entries by query keywords.

    Args:
        query: Space-separated keyword string to match against entries.
        source: Optional source tag appended to result source field.

    Returns:
        List of matching threat intel entries from the bundled database.
    """
    from threat_intel import load_bundled_db
    entries = load_bundled_db()
    if not entries:
        return []

    query_lower = query.lower()
    keywords = query_lower.split()

    results = []
    for entry in entries:
        text = (
            f"{entry.get('title', '')} "
            f"{entry.get('description', '')} "
            f"{entry.get('category', '')}"
        ).lower()
        if any(kw in text for kw in keywords):
            results.append({
                "title": entry.get("title", ""),
                "description": entry.get("description", ""),
                "severity": entry.get("severity", "MEDIUM"),
                "category": entry.get("category", ""),
                "references": entry.get("references", []),
                "source": f"bundled_db ({entry.get('id', 'unknown')})"
            })

    if results:
        logger.info(
            f"Bundled DB returned {len(results)} matches for '{query}'"
        )
    return results


# --- MODULE 1: CODE4RENA SCRAPER ---
def fetch_c4_findings(keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch Code4rena findings for given keywords.

    Falls back to the bundled threat intelligence database when offline
    or when ``config.threat_intel.offline_mode`` is True.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Code4rena findings.
    """
    # Check offline mode
    try:
        if get_config().threat_intel.offline_mode:
            logger.info(
                "Offline mode enabled — skipping Code4rena network call, "
                "using bundled threat intelligence database"
            )
            return _filter_bundled_db(" ".join(keywords), "c4")
    except Exception:
        pass

    print(f"    [*] Querying Code4rena (GitHub)...")
    query = f"org:code-423n4 is:issue label:\"3 (High Risk)\" {' '.join(keywords)}"
    params = {"q": query, "sort": "created", "order": "desc", "per_page": 3}

    try:
        resp = resilient_get(
            C4_API_URL,
            params=params,
            timeout=get_c4_timeout(),
            max_retries=3,
            rate_limiter=get_rate_limiter()
        )
        return resp.json().get("items", [])
    except Exception as e:
        logger.warning(
            f"Network unavailable for Code4rena — using bundled threat "
            f"intelligence database: {e}"
        )
        return _filter_bundled_db(" ".join(keywords), "c4")
    return []

# Backwards compatibility alias
search_c4_findings = fetch_c4_findings

# --- MODULE 2: IMMUNEFI RSS PARSER ---
def fetch_immunefi_reports(keywords: List[str]) -> List[Dict[str, Any]]:
    """Fetch Immunefi reports for given keywords.

    Falls back to the bundled threat intelligence database when offline
    or when ``config.threat_intel.offline_mode`` is True.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Immunefi report dictionaries.
    """
    # Check offline mode
    try:
        if get_config().threat_intel.offline_mode:
            logger.info(
                "Offline mode enabled — skipping Immunefi network call, "
                "using bundled threat intelligence database"
            )
            return _filter_bundled_db(" ".join(keywords), "immunefi")
    except Exception:
        pass

    print(f"    [*] Querying Immunefi (Medium RSS)...")
    reports = []
    try:
        resp = resilient_get(
            IMMUNEFI_RSS,
            timeout=get_immunefi_timeout(),
            max_retries=3,
            rate_limiter=get_rate_limiter()
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
        logger.warning(
            f"Network unavailable for Immunefi — using bundled threat "
            f"intelligence database: {e}"
        )
        return _filter_bundled_db(" ".join(keywords), "immunefi")

    return reports

# --- MODULE 3: SOLODIT DEEP LINKER ---
def generate_solodit_links(keywords: List[str]) -> List[Dict[str, str]]:
    """Generate Solodit deep links for given keywords.

    Since Solodit is hard to scrape (React), we generate precise Deep Links.
    Falls back to the bundled threat intelligence database when offline
    or when ``config.threat_intel.offline_mode`` is True.

    Args:
        keywords: List of search keywords.

    Returns:
        List of Solodit link dictionaries.
    """
    # Check offline mode
    try:
        if get_config().threat_intel.offline_mode:
            logger.info(
                "Offline mode enabled — skipping Solodit link generation, "
                "using bundled threat intelligence database"
            )
            return _filter_bundled_db(" ".join(keywords), "solodit")
    except Exception:
        pass

    try:
        links = []
        for k in keywords:
            # Construct a query for High Severity + Keyword
            # Solodit query param format is usually ?q=KEYWORD
            query = quote(k)
            url = f"{SOLODIT_BASE}?q={query}&min_severity=HIGH"
            links.append({
                "title": f"Solodit Search: High Severity '{k}' Bugs",
                "url": url,
                "source": "Solodit"
            })
        return links
    except Exception as e:
        logger.warning(
            f"Network unavailable for Solodit — using bundled threat "
            f"intelligence database: {e}"
        )
        return _filter_bundled_db(" ".join(keywords), "solodit")

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
