#!/usr/bin/env python3
"""
Unified Threat Intelligence Launcher
Auto-detects EVM (Solidity) vs Solana (Rust) and routes to appropriate engine.

Usage:
    python threat_intel.py contracts/MyToken.sol        # EVM
    python threat_intel.py programs/my_program/lib.rs   # Solana
"""

from __future__ import annotations

import argparse
from pathlib import Path

# Import both engines
import knowledge_fetcher  # EVM intelligence
import solana_intel       # Solana intelligence

from logger import get_logger
from exceptions import SentinelAPIError, SentinelValidationError

logger = get_logger(__name__)


def detect_chain_type(filepath: str) -> str:
    """Auto-detect if file is Solidity (EVM) or Rust (Solana).

    Args:
        filepath: Path to the file to analyze.

    Returns:
        Chain type string: "EVM", "SOLANA", or "UNKNOWN".
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
        except (IOError, OSError, UnicodeDecodeError) as e:
            logger.warning(f"Could not read file for chain detection: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during chain detection: {e}")
    
    return "UNKNOWN"


def main() -> None:
    """Main entry point for the unified threat intelligence CLI."""
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
        logger.info(f"Chain type FORCED to: {chain_type}")
        print(f"[*] Chain type FORCED to: {chain_type}")
    else:
        chain_type = detect_chain_type(args.file)
        logger.info(f"Auto-detected chain type: {chain_type}")
        print(f"[*] Auto-detected chain type: {chain_type}")
    
    # Route to appropriate engine
    if chain_type == "EVM":
        logger.info("Launching EVM Intelligence Engine")
        print("[*] Launching EVM Intelligence Engine "
              "(Code4rena + Immunefi + Solodit)...")
        try:
            knowledge_fetcher.generate_comprehensive_report(args.file)
        except Exception as e:
            logger.error(f"EVM intelligence engine failed: {e}")
            raise SentinelAPIError(
                "EVM intelligence engine failed",
                details={"file": args.file, "error": str(e)}
            ) from e

    elif chain_type == "SOLANA":
        logger.info("Launching Solana Intelligence Engine")
        print("[*] Launching Solana Intelligence Engine "
              "(Neodyme + Sec3 + OtterSec)...")
        try:
            solana_intel.generate_solana_report(args.file)
        except Exception as e:
            logger.error(f"Solana intelligence engine failed: {e}")
            raise SentinelAPIError(
                "Solana intelligence engine failed",
                details={"file": args.file, "error": str(e)}
            ) from e

    else:
        logger.error(f"Could not detect chain type for: {args.file}")
        print(f"[!] ERROR: Could not detect chain type for '{args.file}'")
        print("[!] Supported: .sol (Solidity/EVM), .rs (Rust/Solana)")
        print("[!] Use --force-chain to override auto-detection")
        raise SentinelValidationError(
            "Could not detect chain type",
            details={"file": args.file, "supported_types": [".sol", ".rs"]}
        )


if __name__ == "__main__":
    main()
