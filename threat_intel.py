#!/usr/bin/env python3
"""
Unified Threat Intelligence Launcher
Auto-detects EVM (Solidity) vs Solana (Rust) and routes to appropriate engine.

Usage:
    python threat_intel.py contracts/MyToken.sol        # EVM
    python threat_intel.py programs/my_program/lib.rs   # Solana
"""

import sys
import argparse
from pathlib import Path

# Import both engines
import knowledge_fetcher  # EVM intelligence
import solana_intel       # Solana intelligence


def detect_chain_type(filepath: str) -> str:
    """
    Auto-detect if file is Solidity (EVM) or Rust (Solana).
    """
    extension = Path(filepath).suffix.lower()
    
    if extension == ".sol":
        return "EVM"
    elif extension == ".rs":
        return "SOLANA"
    else:
        # Try to guess from content
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read(500)  # First 500 chars
                if "pragma solidity" in content or "contract " in content:
                    return "EVM"
                elif "use anchor_lang" in content or "#[program]" in content:
                    return "SOLANA"
        except Exception:
            pass
    
    return "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(
        description="🧠 Unified Threat Intelligence Engine (EVM + Solana)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s contracts/MyVault.sol          # Queries Code4rena, Immunefi, Solodit (EVM)
  %(prog)s programs/staking/lib.rs        # Queries Neodyme, Sec3, OtterSec (Solana)
        """
    )
    parser.add_argument(
        "file",
        help="Path to smart contract file (.sol for EVM, .rs for Solana)"
    )
    parser.add_argument(
        "--force-chain",
        choices=["EVM", "SOLANA"],
        help="Override auto-detection and force specific chain"
    )
    
    args = parser.parse_args()
    
    # Detect chain type
    if args.force_chain:
        chain_type = args.force_chain
        print(f"[*] Chain type FORCED to: {chain_type}")
    else:
        chain_type = detect_chain_type(args.file)
        print(f"[*] Auto-detected chain type: {chain_type}")
    
    # Route to appropriate engine
    if chain_type == "EVM":
        print("[*] Launching EVM Intelligence Engine (Code4rena + Immunefi + Solodit)...")
        knowledge_fetcher.generate_comprehensive_report(args.file)
        
    elif chain_type == "SOLANA":
        print("[*] Launching Solana Intelligence Engine (Neodyme + Sec3 + OtterSec)...")
        solana_intel.generate_solana_report(args.file)
        
    else:
        print(f"[!] ERROR: Could not detect chain type for '{args.file}'")
        print("[!] Supported file types: .sol (Solidity/EVM), .rs (Rust/Solana)")
        print("[!] Use --force-chain to override auto-detection")
        sys.exit(1)


if __name__ == "__main__":
    main()
