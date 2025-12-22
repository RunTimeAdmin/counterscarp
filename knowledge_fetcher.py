import requests
import argparse
import sys
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote

# --- CONFIGURATION ---
# GitHub API for Code4rena
C4_API_URL = "https://api.github.com/search/issues"

# Immunefi publishes reports on Medium. We use the RSS feed to fetch the latest "School of Rock" / Spotlights.
IMMUNEFI_RSS = "https://medium.com/feed/immunefi"

# Solodit URL constructor
SOLODIT_BASE = "https://solodit.xyz/search"

def get_contract_context(filepath):
    """
    Scans the file to determine specific tags (e.g., "ERC4626", "Oracle").
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
    except Exception:
        pass
    
    # Default to generic if nothing found
    if not tags: tags.add("Smart Contract")
    return list(tags)

# Backwards compatibility alias
scan_file_for_context = get_contract_context

# --- MODULE 1: CODE4RENA SCRAPER ---
def fetch_c4_findings(keywords):
    print(f"    [*] Querying Code4rena (GitHub)...")
    query = f"org:code-423n4 is:issue label:\"3 (High Risk)\" {' '.join(keywords)}"
    params = {"q": query, "sort": "created", "order": "desc", "per_page": 3}
    
    try:
        resp = requests.get(C4_API_URL, params=params, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("items", [])
    except Exception as e:
        print(f"    [!] C4 Connection Failed: {e}")
    return []

# Backwards compatibility alias
search_c4_findings = fetch_c4_findings

# --- MODULE 2: IMMUNEFI RSS PARSER ---
def fetch_immunefi_reports(keywords):
    print(f"    [*] Querying Immunefi (Medium RSS)...")
    reports = []
    try:
        resp = requests.get(IMMUNEFI_RSS, timeout=5)
        if resp.status_code != 200: return []

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
            if len(reports) >= 3: break
            
    except Exception as e:
        print(f"    [!] Immunefi RSS Failed: {e}")
    
    return reports

# --- MODULE 3: SOLODIT DEEP LINKER ---
def generate_solodit_links(keywords):
    """
    Since Solodit is hard to scrape (React), we generate precise Deep Links.
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
def generate_comprehensive_report(filepath):
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
    parser = argparse.ArgumentParser(description="Multi-Source Knowledge Fetcher")
    parser.add_argument("file", help="The solidity file to analyze context for")
    args = parser.parse_args()
    
    generate_comprehensive_report(args.file)
