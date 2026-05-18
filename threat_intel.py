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
import json
import os
from functools import lru_cache
from pathlib import Path

# Import both engines
import knowledge_fetcher  # EVM intelligence
import solana_intel       # Solana intelligence

from logger import get_logger
from exceptions import CounterscarpAPIError, CounterscarpValidationError
from path_security import sanitize_cli_path

logger = get_logger(__name__)


@lru_cache(maxsize=1)
def load_bundled_db(db_path: str | None = None) -> list:
    """Load the bundled offline threat intelligence database.

    Args:
        db_path: Path to the bundled threat intel JSON database.
            If None, defaults to data/threat_intel_db.json relative to
            this file.

    Returns:
        List of threat intelligence entries, or empty list on failure.
    """
    if db_path is None:
        db_path = os.path.join(
            os.path.dirname(__file__), "data", "threat_intel_db.json"
        )
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data: list = json.load(f)
        logger.info(
            f"Loaded bundled threat intel database: {len(data)} entries"
        )
        return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to load bundled threat intel DB: {e}")
        return []


def detect_chain_type(filepath: str) -> str:
    """Auto-detect if file is Solidity (EVM) or Rust (Solana).

    Args:
        filepath: Path to the file to analyze.

    Returns:
        Chain type string: "EVM", "SOLANA", or "UNKNOWN".
    """
    safe_file = sanitize_cli_path(filepath)
    extension = Path(safe_file).suffix.lower()
    
    if extension == ".sol":
        return "EVM"
    elif extension == ".rs":
        return "SOLANA"

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
        type=argparse.FileType("r", encoding="utf-8"),
        help="Path to smart contract file (.sol for EVM, .rs for Solana)"
    )
    parser.add_argument(
        "--force-chain",
        choices=["EVM", "SOLANA"],
        help="Override auto-detection and force specific chain"
    )
    
    args = parser.parse_args()
    safe_file = str(
        sanitize_cli_path(
            args.file.name,
            allowed_suffixes={".sol", ".rs"},
        )
    )
    source = args.file.read()
    
    # Detect chain type
    if args.force_chain:
        chain_type = args.force_chain
        logger.info(f"Chain type FORCED to: {chain_type}")
        print(f"[*] Chain type FORCED to: {chain_type}")
    else:
        chain_type = detect_chain_type(safe_file)
        logger.info(f"Auto-detected chain type: {chain_type}")
        print(f"[*] Auto-detected chain type: {chain_type}")
    
    # Route to appropriate engine
    if chain_type == "EVM":
        logger.info("Launching EVM Intelligence Engine")
        print("[*] Launching EVM Intelligence Engine "
              "(Code4rena + Immunefi + Solodit)...")
        try:
            knowledge_fetcher.generate_comprehensive_report_from_source(
                source,
                source_name=safe_file,
            )
        except Exception as e:
            logger.error(f"EVM intelligence engine failed: {e}")
            raise CounterscarpAPIError(
                "EVM intelligence engine failed",
                details={"file": safe_file, "error": str(e)}
            ) from e

    elif chain_type == "SOLANA":
        logger.info("Launching Solana Intelligence Engine")
        print("[*] Launching Solana Intelligence Engine "
              "(Neodyme + Sec3 + OtterSec)...")
        try:
            solana_intel.generate_solana_report_from_source(
                source,
                source_name=safe_file,
            )
        except Exception as e:
            logger.error(f"Solana intelligence engine failed: {e}")
            raise CounterscarpAPIError(
                "Solana intelligence engine failed",
                details={"file": safe_file, "error": str(e)}
            ) from e

    else:
        logger.error(f"Could not detect chain type for: {safe_file}")
        print(f"[!] ERROR: Could not detect chain type for '{safe_file}'")
        print("[!] Supported: .sol (Solidity/EVM), .rs (Rust/Solana)")
        print("[!] Use --force-chain to override auto-detection")
        raise CounterscarpValidationError(
            "Could not detect chain type",
            details={"file": safe_file, "supported_types": [".sol", ".rs"]}
        )


if __name__ == "__main__":
    main()
