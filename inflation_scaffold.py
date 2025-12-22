import os
import argparse
from textwrap import dedent


TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
// TODO: adjust token and vault imports to match your project
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
        // TODO: wire this to your real vault and asset.
        // Example (adjust to your constructor signature):
        // asset = new ERC20("Mock", "MCK", 18);
        // vault = new {vault_contract}(asset);

        vm.skip(true); // REMOVE this once you have real wiring above.

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

    project_root = os.path.abspath(args.project_root)
    vault_contract = args.vault_contract

    target_dir = os.path.join(project_root, "test", "invariant")
    os.makedirs(target_dir, exist_ok=True)

    filename = f"{vault_contract}Inflation.t.sol"
    target_path = os.path.join(target_dir, filename)

    if os.path.exists(target_path):
        print(f"[!] File already exists: {target_path}")
        return

    content = TEMPLATE.format(vault_contract=vault_contract)

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)

    print("[+] Inflation invariant scaffold created:")
    print(f"    {target_path}")
    print("[!] IMPORTANT: Edit the TODOs to wire in your real vault and asset before running:")
    print("    forge test --match-contract {vault}InflationTest -vvv".format(vault=vault_contract))


if __name__ == "__main__":
    main()
