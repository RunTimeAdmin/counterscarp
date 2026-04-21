from __future__ import annotations

import subprocess
import re
import argparse
import sys
from typing import List, Dict, Any, Optional

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


# CONFIGURATION
# How many random scenarios to generate?
# 500 is quick checks. 10,000+ is for deep audits.
DEFAULT_FUZZ_RUNS = 1000


def get_fuzz_runs() -> int:
    """Get fuzz runs from config or use default."""
    try:
        # Try external_tools first, then fuzzing.foundry
        config = get_config()
        if hasattr(config, 'external_tools') and config.external_tools:
            runs = config.external_tools.foundry_fuzz_runs
            if runs:
                return runs
        # Fallback to fuzzing config
        return config.fuzzing.foundry_runs
    except Exception:
        return DEFAULT_FUZZ_RUNS


def run_foundry_fuzz(
    target_contract: str,
    match_test: Optional[str] = None,
    fuzz_runs: Optional[int] = None,
    stderr_log: Optional[str] = None
) -> str:
    """Runs `forge test` specifically targeting invariant tests.

    Args:
        target_contract: Name of the contract to fuzz.
        match_test: Optional specific test function to run.
        fuzz_runs: Number of fuzz runs (default: from config or 1000).

    Returns:
        Raw stdout from the fuzzing run.

    Raises:
        CounterscarpToolNotFoundError: If Foundry is not installed.
        CounterscarpTimeoutError: If fuzzing times out.
        CounterscarpAnalysisError: If fuzzing fails.
    """
    # Use config value if not provided
    if fuzz_runs is None:
        fuzz_runs = get_fuzz_runs()

    print("[*] Initializing Fuzz Engine (Foundry)...")
    print(f"[*] Target: {target_contract}")
    print(f"[*] Runs: {fuzz_runs} attempts per invariant")

    cmd = [
        "forge",
        "test",
        "--match-contract",
        target_contract,
        "--fuzz-runs",
        str(fuzz_runs),
        "-vvv",  # Verbosity 3 is required to see Counterexamples
    ]

    if match_test:
        cmd.extend(["--match-test", match_test])

    try:
        # We assume the user is in the root of a Foundry project
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if result.stderr:
            append_stderr_log(result.stderr, "forge-fuzz", stderr_log)
        return result.stdout
    except FileNotFoundError as e:
        logger.error("Foundry (forge) not found")
        raise CounterscarpToolNotFoundError(
            "Foundry not found in PATH",
            details={
                "tool": "forge",
                "install_cmd": "curl -L https://foundry.paradigm.xyz | bash"
            }
        ) from e
    except PermissionError as e:
        logger.error(f"Permission denied running Foundry: {e}")
        raise CounterscarpAnalysisError(
            "Permission denied running Foundry",
            details={"error": str(e)}
        ) from e
    except subprocess.TimeoutExpired as e:
        logger.error("Foundry fuzzing timed out")
        raise CounterscarpTimeoutError(
            "Foundry fuzzing timed out",
            details={"operation": "foundry_fuzzing"}
        ) from e


def parse_counterexamples(log_output: str) -> List[Dict[str, Any]]:
    """Scrapes the 'Counterexample' block from Foundry output.

    This is the specific sequence of calls that broke the contract.

    Args:
        log_output: Raw log output from Foundry.

    Returns:
        List of exploit dictionaries containing test_name, reason, and steps.
    """
    exploits: List[Dict] = []

    # Regex to find the test name and the failure block
    # Looks for: "[FAIL. Reason: ... ] testName()"
    fail_pattern = re.compile(r"\[FAIL\. Reason: (.*?)\]\s+(\w+)\(.*\)")

    # Split output into lines for easier processing
    lines = log_output.split("\n")

    current_exploit: Dict | None = None
    capture_mode = False

    for line in lines:
        clean_line = line.strip()

        # 1. Detect a Failure
        fail_match = fail_pattern.search(clean_line)
        if fail_match:
            if current_exploit:
                # Save previous if exists
                exploits.append(current_exploit)

            current_exploit = {
                "test_name": fail_match.group(2),
                "reason": fail_match.group(1),
                "steps": [],
            }
            continue

        # 2. Detect start of Counterexample trace
        if "Counterexample:" in clean_line:
            capture_mode = True
            continue

        # 3. Capture the Steps (The "Kill Shot")
        # Foundry invariant traces look like:
        # sender=0x... addr=[src] calldata=deposit(uint256) args=[18]
        if capture_mode and current_exploit:
            # Stop capturing if we hit another test or summary lines
            if clean_line.startswith("Ran") or clean_line.startswith("Suite"):
                capture_mode = False
                exploits.append(current_exploit)
                current_exploit = None
                continue

            # Extract the function call and args
            # This is a loose match to catch various Foundry output formats
            if "calldata=" in clean_line or "args=" in clean_line:
                current_exploit["steps"].append(clean_line)
            # Simple unit test fuzzing counterexample (function_name(args))
            elif "(" in clean_line and ")" in clean_line and capture_mode:
                current_exploit["steps"].append(clean_line)

    # Catch the last one if loop finished
    if current_exploit:
        exploits.append(current_exploit)

    return exploits


def print_attack_report(exploits: List[Dict[str, Any]]) -> None:
    """Print a formatted report of fuzzing exploits.

    Args:
        exploits: List of exploit dictionaries to report.
    """
    logger.info(f"Fuzzing report: {len(exploits)} invariants broken")
    print("\n" + "=" * 60)
    print(f" FUZZING REPORT - {len(exploits)} INVARIANTS BROKEN")
    print("=" * 60 + "\n")

    if not exploits:
        print("[+] STATUS: ROBUST. No invariants broken in this run.")
        return

    for ex in exploits:
        print(f"\033[91m[VULNERABLE] {ex['test_name']} \033[0m")
        print(f"  Reason: {ex['reason']}")
        print("  Attack Vector (The 'Kill Shot'):")
        for step in ex["steps"]:
            # Highlight the args for visibility
            step_fmt = step.replace("args=[", "\033[93margs[").replace("]", "]\033[0m")
            print(f"    -> {step_fmt}")
        print("-" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Wrapper for Foundry to automate invariant checking.",
    )
    parser.add_argument(
        "contract",
        help="The name of the Test contract (e.g., InvariantTest)",
    )
    parser.add_argument(
        "--test",
        help="Specific test function to run",
        default=None,
    )
    args = parser.parse_args()

    try:
        raw_logs = run_foundry_fuzz(args.contract, args.test)

        # Debug: verify raw output if needed
        # print(raw_logs)

        attacks = parse_counterexamples(raw_logs)
        print_attack_report(attacks)
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        raise
