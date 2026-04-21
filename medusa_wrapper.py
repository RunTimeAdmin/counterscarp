#!/usr/bin/env python3
"""
Medusa Fuzzer Wrapper
Coverage-guided fuzzing for smart contracts (next-gen Echidna)
Requires: Medusa binary installed (https://github.com/crytic/medusa)
"""

from __future__ import annotations

import subprocess
import json
import sys
import os
import argparse
from typing import Dict, Any, List, Optional

from logger import get_logger, append_stderr_log
from exceptions import (
    CounterscarpAnalysisError,
    CounterscarpToolNotFoundError,
    CounterscarpTimeoutError,
)

# Import config loader
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None


def get_config() -> CounterscarpConfig:
    """Get or load the configuration."""
    global _config
    if _config is None:
        if CONFIG_AVAILABLE:
            try:
                _config = load_config()
            except Exception:
                _config = CounterscarpConfig()
        else:
            _config = CounterscarpConfig()
    return _config


def get_medusa_timeout() -> int:
    """Get Medusa timeout from config or use default."""
    try:
        return get_config().fuzzing.medusa_timeout
    except Exception:
        return 300


def get_medusa_test_limit() -> int:
    """Get Medusa test limit from config or use default."""
    try:
        return get_config().fuzzing.medusa_test_limit
    except Exception:
        return 100000


def check_medusa_installed() -> bool:
    """Check if Medusa is available on the system.

    Returns:
        True if Medusa is installed and accessible, False otherwise.
    """
    try:
        result = subprocess.run(
            ["medusa", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.debug("Medusa not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("Medusa version check timed out")
        return False
    except Exception as e:
        logger.warning(f"Error checking Medusa installation: {e}")
        return False


def run_medusa_fuzz(
    project_root: str,
    target_contract: Optional[str] = None,
    test_limit: Optional[int] = None,
    timeout: Optional[int] = None,
    stderr_log: Optional[str] = None
) -> Dict[str, Any]:
    """Run Medusa fuzzer on a Foundry/Hardhat project.

    Args:
        project_root: Path to project root (must contain foundry.toml or
            hardhat.config).
        target_contract: Optional specific contract to fuzz.
        test_limit: Maximum number of sequences to run (default: from config
            or 100k).
        timeout: Max execution time in seconds (default: from config or
            5 minutes).

    Returns:
        Dict with findings, coverage data, and statistics.

    Raises:
        CounterscarpToolNotFoundError: If Medusa is not installed.
        CounterscarpTimeoutError: If fuzzing times out.
        CounterscarpAnalysisError: If fuzzing fails.
    """
    # Use config values if not provided
    if test_limit is None:
        test_limit = get_medusa_test_limit()
    if timeout is None:
        timeout = get_medusa_timeout()
    if not check_medusa_installed():
        logger.error("Medusa not installed")
        print("[!] Medusa not installed. Install: https://github.com/crytic/medusa")
        print("    Quick install: go install github.com/crytic/medusa/cmd/medusa@latest")
        raise CounterscarpToolNotFoundError(
            "Medusa not found in PATH",
            details={
                "tool": "medusa",
                "install_cmd": "go install github.com/crytic/medusa/cmd/medusa@latest"
            }
        )
    
    # Build command
    cmd = [
        "medusa",
        "fuzz",
        "--target", project_root,
        "--test-limit", str(test_limit),
        "--timeout", str(timeout),
        "--deployment-order", "ContractName",  # Auto-detect
        "--coverage-enabled",
        "--json-output"
    ]
    
    if target_contract:
        cmd.extend(["--contract-name", target_contract])
    
    logger.info(f"Running Medusa fuzzer on {project_root}")
    logger.debug(f"Test limit: {test_limit}, Timeout: {timeout}s")
    print(f"[*] Running Medusa fuzzer on {project_root}")
    print(f"[*] Test limit: {test_limit} sequences, Timeout: {timeout}s")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout + 30
        )
        if result.stderr:
            append_stderr_log(result.stderr, "medusa", stderr_log)
        return parse_medusa_output(result.stdout, result.stderr)
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Medusa timed out after {timeout}s")
        raise CounterscarpTimeoutError(
            "Medusa fuzzing timed out",
            details={
                "operation": "medusa_fuzzing",
                "timeout_seconds": timeout
            }
        ) from e
    except FileNotFoundError as e:
        logger.error(f"Medusa not found during execution: {e}")
        raise CounterscarpToolNotFoundError(
            "Medusa not found in PATH",
            details={"tool": "medusa"}
        ) from e
    except PermissionError as e:
        logger.error(f"Permission denied running Medusa: {e}")
        raise CounterscarpAnalysisError(
            "Permission denied running Medusa",
            details={"error": str(e)}
        ) from e
    except Exception as e:
        logger.error(f"Error running Medusa: {e}")
        raise CounterscarpAnalysisError(
            "Medusa fuzzing failed",
            details={"error": str(e)}
        ) from e


def parse_medusa_output(stdout: str, stderr: str) -> Dict[str, Any]:
    """Parse Medusa JSON output and extract findings.

    Medusa output format:
    {
      "results": [
        {
          "test": "invariant_name",
          "status": "FAILED",
          "call_sequence": [...],
          "shrunk": true
        }
      ],
      "coverage": {...},
      "statistics": {...}
    }

    Args:
        stdout: Standard output from Medusa.
        stderr: Standard error from Medusa.

    Returns:
        Parsed results dictionary with findings, coverage, and statistics.
    """
    findings = []
    coverage_data = {}
    stats = {}
    
    # Try to parse JSON output
    try:
        # Medusa may output multiple JSON objects, take the last one
        json_blocks = [line for line in stdout.split('\n') if line.strip().startswith('{')]
        if json_blocks:
            data = json.loads(json_blocks[-1])
            
            # Extract test results
            if "results" in data:
                for result in data["results"]:
                    if result.get("status") in ["FAILED", "REVERTED"]:
                        findings.append({
                            "test": result.get("test", "unknown"),
                            "status": result["status"],
                            "call_sequence": result.get("call_sequence", []),
                            "shrunk": result.get("shrunk", False),
                            "error": result.get("error", "Invariant violation")
                        })
            
            # Extract coverage
            coverage_data = data.get("coverage", {})
            
            # Extract statistics
            stats = data.get("statistics", {})
    
    except json.JSONDecodeError:
        # Fallback: Parse text output
        if "Assertion failed" in stdout or "Failed invariant" in stdout:
            findings.append({
                "test": "unknown",
                "status": "FAILED",
                "error": "Parse stdout for details"
            })
    
    return {
        "findings": findings,
        "coverage": coverage_data,
        "statistics": stats,
        "total_sequences": stats.get("sequences_run", 0),
        "raw_output": stdout
    }


def generate_medusa_config(project_root: str, target_contract: str) -> str:
    """Generate medusa.json configuration file.

    Example config:
    {
      "fuzzing": {
        "workers": 10,
        "testLimit": 100000,
        "timeout": 0,
        "corpusDirectory": "medusa-corpus"
      },
      "compilation": {
        "platform": "foundry"
      }
    }

    Args:
        project_root: Path to the project root directory.
        target_contract: Name of the contract to target.

    Returns:
        Path to the generated configuration file.
    """
    config = {
        "fuzzing": {
            "workers": 10,
            "testLimit": 100000,
            "timeout": 0,
            "corpusDirectory": "medusa-corpus",
            "coverageEnabled": True
        },
        "compilation": {
            "platform": "foundry",  # or "hardhat"
            "targetContracts": [target_contract] if target_contract else []
        },
        "logging": {
            "level": "info",
            "jsonOutput": True
        }
    }
    
    config_path = os.path.join(project_root, "medusa.json")
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    return config_path


def print_results(results: Dict[str, Any]) -> None:
    """Pretty-print Medusa fuzzing results.

    Args:
        results: Results dictionary from run_medusa_fuzz().
    """
    print("\n" + "="*60)
    print(" MEDUSA FUZZING RESULTS")
    print("="*60)
    
    if "error" in results:
        print(f"\n[!] ERROR: {results['error']}")
        return
    
    findings = results.get("findings", [])
    stats = results.get("statistics", {})
    
    print(f"\n[*] Total sequences run: {results.get('total_sequences', 'unknown')}")
    print(f"[*] Coverage: {stats.get('coverage_percent', 'N/A')}%")
    
    if not findings:
        print("\n✅ No invariant violations found!")
        print("   All properties held across all fuzz sequences.")
        return
    
    print(f"\n⚠️  Found {len(findings)} invariant violations:\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"[{i}] Test: {finding['test']}")
        print(f"    Status: {finding['status']}")
        print(f"    Error: {finding.get('error', 'Unknown')}")
        
        if finding.get("shrunk"):
            print("    ✓ Call sequence minimized (shrunk)")
        
        call_seq = finding.get("call_sequence", [])
        if call_seq:
            print(f"    Call sequence ({len(call_seq)} calls):")
            for j, call in enumerate(call_seq[:5], 1):  # Show first 5
                print(f"      {j}. {call.get('function', 'unknown')}({call.get('args', '')})")
            if len(call_seq) > 5:
                print(f"      ... ({len(call_seq) - 5} more calls)")
        
        print("-" * 60)


def main() -> None:
    """Main entry point for the Medusa wrapper CLI."""
    parser = argparse.ArgumentParser(
        description="Medusa fuzzer wrapper - Coverage-guided property testing for smart contracts"
    )
    parser.add_argument(
        "project_root",
        help="Path to Foundry/Hardhat project root"
    )
    parser.add_argument(
        "--contract",
        help="Specific contract to fuzz (optional)"
    )
    parser.add_argument(
        "--test-limit",
        type=int,
        default=100000,
        help="Maximum number of sequences to run (default: 100k)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Maximum execution time in seconds (default: 300)"
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate medusa.json config file and exit"
    )
    
    args = parser.parse_args()
    
    if args.generate_config:
        config_path = generate_medusa_config(args.project_root, args.contract)
        print(f"[+] Generated Medusa config: {config_path}")
        print("[*] Edit the config, then run: medusa fuzz")
        return
    
    results = run_medusa_fuzz(
        args.project_root,
        target_contract=args.contract,
        test_limit=args.test_limit,
        timeout=args.timeout
    )
    
    print_results(results)


if __name__ == "__main__":
    main()
