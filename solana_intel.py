import requests
import argparse
import sys
import json

# --- CONFIGURATION ---
# The "Big Three" Solana Audit Repos (Publicly indexed data)
SOURCES = {
    "Neodyme": "https://api.github.com/search/issues?q=org:neodyme+is:issue+label:\"vulnerability\"",
    "Solana-Labs": "https://api.github.com/search/issues?q=repo:solana-labs/solana+label:\"security\"",
    # Solodit is still the best aggregator, we just filter for Solana
    "Solodit_DeepLink": "https://solodit.xyz/search?q={KEYWORD}&ecosystem=SOLANA"
}

# Key Context Indicators for Solana (Rust/Anchor)
CONTEXT_KEYWORDS = {
    "anchor": ["anchor_lang", "#[program]", "Context<"],
    "spl-token": ["spl_token", "token::Transfer"],
    "staking": ["stake_pool", "voter", "locking"],
    "cpi": ["invoke", "invoke_signed", "CpiContext"],
    "discriminator": ["account_discriminator", "unsafe"]
}

def detect_program_context(filepath):
    """
    Scans a Rust (.rs) file to guess the program type (Anchor, Native, SPL).
    """
    detected_tags = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Check for Anchor Framework
            if "anchor_lang" in content: 
                detected_tags.add("Anchor Framework")
            
            # Check for specific patterns
            for tag, patterns in CONTEXT_KEYWORDS.items():
                if any(p in content for p in patterns):
                    detected_tags.add(tag)
                    
    except Exception as e:
        print(f"    [!] Error reading file: {e}")
    
    if not detected_tags: detected_tags.add("Solana Program")
    return list(detected_tags)

def fetch_github_issues(api_url):
    """
    Generic fetcher for GitHub Search API.
    """
    try:
        # User-Agent is often required by GitHub API to avoid blocking
        headers = {"User-Agent": "SolanaIntelFetcher/1.0"}
        resp = requests.get(api_url, headers=headers, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("items", [])
    except Exception as e:
        print(f"    [!] Connection Error: {e}")
    return []

def generate_solana_report(filepath):
    """
    Main intelligence gathering function for Solana programs.
    Returns structured data for programmatic use.
    """
    print("\n" + "="*70)
    print(f" 🦀 SOLANA INTELLIGENCE ENGINE (Sec3 / Neodyme / OtterSec)")
    print("="*70)
    
    # 1. Context Detection
    tags = detect_program_context(filepath)
    print(f"[*] Program Context: {', '.join(tags)}")
    
    # Define search keywords based on context
    search_term = "solana"
    if "Anchor Framework" in tags: search_term += "+anchor"
    if "spl-token" in tags: search_term += "+spl"
    
    print("-" * 70)

    # 2. Querying Neodyme (via GitHub Issues/Repo Search)
    print(f"[*] Searching Neodyme Public Disclosures...")
    # Adjust query to search specifically for the context
    neodyme_url = f"https://api.github.com/search/issues?q=org:neodyme+{search_term}+is:issue"
    neodyme_data = fetch_github_issues(neodyme_url)
    
    if neodyme_data:
        for item in neodyme_data[:3]:
            print(f"  • [Neodyme] {item['title']}")
            print(f"    Url: {item['html_url']}")
    else:
        print("  • No direct matches in public repo.")

    # 3. Querying Solana Labs (Core Protocol Bugs)
    # Useful if you are using low-level native features
    print(f"\n[*] Searching Solana Labs Security Issues...")
    solana_data = fetch_github_issues(SOURCES["Solana-Labs"])
    if solana_data:
        for item in solana_data[:2]:
            print(f"  • [Core] {item['title']}")
            print(f"    Url: {item['html_url']}")
    else:
        print("  • No direct matches in core security issues.")

    # 4. Solodit Deep Links (The Aggregator)
    print(f"\n[*] Solodit Research Links (Solana Filtered):")
    solodit_links = []
    # Generate a deep link for each major tag
    for tag in tags:
        clean_tag = tag.split(" ")[0]  # "Anchor Framework" -> "Anchor"
        link = SOURCES["Solodit_DeepLink"].format(KEYWORD=clean_tag)
        print(f"  • Search Solodit for '{clean_tag}' bugs")
        print(f"    Url: {link}")
        solodit_links.append({"tag": clean_tag, "url": link})

    # 5. OtterSec / Sec3 (Manual Reference)
    # Since they don't have an easily scrapable API for reports, we provide the best static links
    print(f"\n[*] Manual Reference Libraries (Bookmark These):")
    print(f"  • OtterSec Reports: https://github.com/ottersec/audits")
    print(f"  • Sec3 Vulnerability Db: https://github.com/sec3-service/vulnerability-list")

    print("\n" + "="*70)
    
    # Return structured data for GUI integration
    return {
        "context": tags,
        "neodyme": neodyme_data[:3],
        "solana_core": solana_data[:2] if solana_data else [],
        "solodit_links": solodit_links
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Solana Security Intelligence Fetcher")
    parser.add_argument("file", help="The .rs file to analyze")
    args = parser.parse_args()
    
    generate_solana_report(args.file)
