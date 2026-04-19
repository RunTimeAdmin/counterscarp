from __future__ import annotations

import re
import argparse
import sys
import os
from typing import List, Dict, Any

# --- CONFIGURATION ---
# Regex to capture function headers:
# function name(...) visibility modifiers returns(...)
FUNCTION_PATTERN = re.compile(
    r"function\s+(\w+)\s*\((.*?)\)\s*(.*?)(?:\{|;)",
    re.DOTALL | re.MULTILINE,
)

# Keywords that indicate a function is Read-Only (Safe)
READ_ONLY_MODIFIERS = ["view", "pure"]

# Modifiers that indicate Authorization (Admin/Restricted)
AUTH_MODIFIERS = ["onlyOwner", "onlyRole", "onlyMinter", "auth", "requiresAuth"]


def parse_solidity_file(filepath: str) -> List[Dict[str, Any]]:
    """Parse a Solidity file and extract function information.

    Args:
        filepath: Path to the Solidity file to parse.

    Returns:
        List of dictionaries containing function information.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Remove comments to avoid false positives
    # (Simple removal of // and /* ... */)
    content = re.sub(r"//.*", "", content)
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

    matches = FUNCTION_PATTERN.findall(content)
    functions: List[Dict] = []

    for match in matches:
        name = match[0]
        params = match[1]  # Not used for matrix but good for debug
        decorators = match[2]

        # Clean up whitespace
        decorators = " ".join(decorators.split())

        # Determine Visibility
        visibility = "default"
        if "external" in decorators:
            visibility = "external"
        elif "public" in decorators:
            visibility = "public"
        elif "internal" in decorators:
            visibility = "internal"
        elif "private" in decorators:
            visibility = "private"

        # Determine Mutability (Read vs Write)
        is_read_only = any(x in decorators for x in READ_ONLY_MODIFIERS)
        state_mutability = "READ" if is_read_only else "WRITE"

        # Extract Modifiers (excluding visibility/mutability keywords)
        keywords = [
            "external",
            "public",
            "internal",
            "private",
            "view",
            "pure",
            "payable",
            "virtual",
            "override",
            "returns",
        ]
        raw_mods = [
            m.strip()
            for m in decorators.split()
            if m.strip() and m not in keywords and "(" not in m
        ]

        # Check for auth
        auth_mechanisms = [
            m for m in raw_mods if any(auth in m for auth in AUTH_MODIFIERS)
        ]
        other_mods = [m for m in raw_mods if m not in auth_mechanisms]

        # RISK ASSESSMENT
        # Critical Risk: External/Public + WRITE + No Auth
        risk = "LOW"
        if state_mutability == "WRITE" and visibility in ["public", "external"]:
            if auth_mechanisms:
                risk = "ADMIN"  # Protected by owner/role
            else:
                risk = "HIGH"  # Anyone can call this! (Open access)

        functions.append(
            {
                "name": name,
                "visibility": visibility,
                "mutability": state_mutability,
                "auth": auth_mechanisms,
                "mods": other_mods,
                "risk": risk,
            }
        )

    return functions


def generate_matrix_report(functions: List[Dict[str, Any]]) -> None:
    """Generate and print an access control matrix report.

    Args:
        functions: List of function information dictionaries.
    """
    print("\n" + "=" * 80)
    print(" 🔑 ACCESS CONTROL MATRIX")
    print("=" * 80)
    print(f"{'RISK':<10} | {'FUNCTION NAME':<25} | {'ACCESS':<10} | {'AUTH / MODIFIERS':<30}")
    print("-" * 80)

    for f in functions:
        # Filter: We usually don't care about internal/private for this matrix
        if f["visibility"] in ["internal", "private"]:
            continue

        # Color Coding
        color = "\033[0m"  # Reset
        risk_label = f["risk"]

        if f["risk"] == "HIGH":
            color = "\033[91m"  # Red (Critical)
            risk_label = "🚨 PUBLIC"
        elif f["risk"] == "ADMIN":
            color = "\033[96m"  # Cyan (Protected)
            risk_label = "🛡️ ADMIN"
        elif f["mutability"] == "READ":
            color = "\033[90m"  # Gray (View only)
            risk_label = "   VIEW"

        # Format Auth/Modifiers
        auth_str = ", ".join(f["auth"]) if f["auth"] else "Anyone"
        if f["mods"]:
            auth_str += f" (+{', '.join(f['mods'])})"

        print(
            f"{color}{risk_label:<10} | {f['name']:<25} | {f['visibility']:<10} | {auth_str}\033[0m"
        )

    print("-" * 80 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate Access Control Matrix from Solidity.",
    )
    parser.add_argument("file", help="The .sol file to analyze")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Error: File {args.file} not found.")
        sys.exit(1)

    data = parse_solidity_file(args.file)
    generate_matrix_report(data)
