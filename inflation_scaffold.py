from __future__ import annotations

import os
import argparse
from path_security import sanitize_cli_path, sanitize_output_path


TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
// ACTION REQUIRED: Verify these import paths match your project layout.
// ERC20 is sourced from solmate; adjust if you use OpenZeppelin or a custom token.
import {ERC20} from "solmate/tokens/ERC20.sol";
import {{{vault_contract}}} from "../src/{vault_contract}.sol";

// This handler exposes the actions the fuzzer can take.
contract {vault_contract}InflationHandler is Test {{
    {vault_contract} public vault;
    ERC20 public asset;

    constructor({vault_contract} _vault, ERC20 _asset) {{
        vault = _vault;
        asset = _asset;
    }}

    // Action A: Standard deposit (victim behavior)
    function deposit(uint256 amount) public {{
        amount = bound(amount, 1, 100 ether);
        deal(address(asset), address(this), amount);
        asset.approve(address(vault), amount);
        vault.deposit(amount, address(this));
    }}

    // Action B: Donation (inflation attack primitive)
    function donate(uint256 amount) public {{
        amount = bound(amount, 1, 100 ether);
        deal(address(asset), address(this), amount);
        asset.transfer(address(vault), amount);
    }}
}}

// Invariant suite for detecting ERC4626-style inflation/donation attacks.
contract {vault_contract}InflationTest is Test {{
    {vault_contract} public vault;
    ERC20 public asset;
    {vault_contract}InflationHandler public handler;

    function setUp() public {{
        // ACTION REQUIRED: Instantiate your vault and underlying asset below.
        // Replace the two lines with your actual constructor calls, e.g.:
        //   asset = new ERC20("Mock", "MCK", 18);
        //   vault = new {vault_contract}(address(asset));
        // Then delete the vm.skip line so the invariants run.

        vm.skip(true); // Remove this line after wiring vault and asset above.

        handler = new {vault_contract}InflationHandler(vault, asset);
        targetContract(address(handler));
    }}

    // INVARIANT: A reasonable deposit must not yield 0 shares.
    function invariant_no_zero_shares_on_deposit() public {{
        uint256 assets = 1 ether;
        uint256 expectedShares = vault.convertToShares(assets);
        assertGt(
            expectedShares,
            0,
            "CRITICAL: Inflation/Donation attack possible (deposit yields 0 shares)."
        );
    }}
}}
"""


def main() -> None:
    """Main entry point for the inflation scaffold CLI.

    Generates a Foundry invariant test template for detecting
    ERC4626-style inflation/donation attacks.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Scaffold a Foundry invariant test for ERC4626-style inflation/donation attacks."
        ),
    )
    parser.add_argument(
        "--project-root",
        required=True,
        help="Path to the Foundry project root (where 'test/' lives)",
    )
    parser.add_argument(
        "--vault-contract",
        required=True,
        help="Name of the vault contract (e.g., MyVault)",
    )
    args = parser.parse_args()

    project_root = str(
        sanitize_cli_path(args.project_root, must_exist=True, expect_file=False)
    )
    vault_contract = args.vault_contract

    target_dir = sanitize_output_path(os.path.join(project_root, "test", "invariant"))
    target_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{vault_contract}Inflation.t.sol"
    target_path = str(target_dir / filename)

    if os.path.exists(target_path):
        print(f"[!] File already exists: {target_path}")
        return

    content = TEMPLATE.format(vault_contract=vault_contract)

    sanitize_output_path(target_path).write_text(content, encoding="utf-8")

    print("[+] Inflation invariant scaffold created:")
    print(f"    {target_path}")
    print("[!] IMPORTANT: Complete the ACTION REQUIRED sections to wire in your real vault and asset before running:")
    print("    forge test --match-contract {vault}InflationTest -vvv".format(vault=vault_contract))


if __name__ == "__main__":
    main()
