// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19; // FLOATING_PRAGMA

/**
 * @title TokenHelper
 * @dev  Intentionally flawed ERC20-like token for cross-contract testing.
 *       Key issues: missing return values on transfer/transferFrom,
 *       unsafe approve pattern, no access control on mint.
 *       DO NOT DEPLOY.
 */
contract TokenHelper {

    string public name = "VulnerableToken";
    string public symbol = "VLT";
    uint8  public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ── Non-standard transfer — no return value ────────────────
    // Violates ERC20: transfer() should return bool
    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        // Missing: return true
    }

    // ── Unsafe approve — sets allowance without zero-check ──────
    // ERC20 approves should require allowance == 0 before setting
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // ── Non-standard transferFrom — no return value ─────────────
    function transferFrom(address from, address to, uint256 amount) external {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        // Missing: return true
    }

    // ── Swap with slippage issues (called by VulnerableVault) ──
    function swap(uint256 amount, uint256 minOut, address recipient) external {
        balanceOf[msg.sender] -= amount;
        // UNSAFE: no validation that minOut is reasonable
        balanceOf[recipient] += minOut;
    }

    // ── Unprotected mint — no access control ────────────────────
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
