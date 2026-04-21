"""
Shared fixtures for Garrison Engine test suite.
"""

import pytest
import tempfile
import os
from pathlib import Path


# =============================================================================
# Sample Contract Fixtures
# =============================================================================

@pytest.fixture
def sample_solidity_contract():
    """A small but realistic Solidity contract with known patterns."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VulnerableVault
 * @notice A vault contract with intentional vulnerabilities for testing
 * @dev This contract has reentrancy and access control issues
 */
contract VulnerableVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    address public admin;
    bool public tradingEnabled;
    
    // Hardcoded address for testing
    address constant TREASURY = 0x1234567890123456789012345678901234567890;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        admin = msg.sender;
        tradingEnabled = false;
    }
    
    /// @notice Deposit ETH into the vault
    /// @dev Anyone can deposit
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /// @notice Withdraw ETH from the vault
    /// @dev Vulnerable to reentrancy - for testing only
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }
    
    /// @notice Emergency withdraw all funds - only owner
    /// @dev This should be protected but isn't
    function emergencyWithdraw() external {
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
    
    /// @notice Drain contract - only owner
    /// @dev Critical function without access control
    function drain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    /// @notice Set new admin - only current admin
    /// @dev Should check tx.origin vs msg.sender
    function setAdmin(address newAdmin) external {
        require(tx.origin == admin, "Not authorized");
        admin = newAdmin;
    }
    
    /// @notice Upgrade the contract
    /// @dev Should be protected
    function upgradeTo(address newImplementation) external {
        // Missing access control
    }
    
    /// @notice Set trading status
    /// @dev Owner can enable/disable trading
    function setTradingEnabled(bool enabled) external onlyOwner {
        tradingEnabled = enabled;
    }
    
    /// @notice Get contract balance
    /// @dev View function
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /// @notice Unsafe external call
    /// @dev Missing return value check
    function unsafeTransfer(address target, uint256 amount) external {
        // This is a comment with tx.origin - should not trigger
        target.call{value: amount}("");
    }
    
    /// @notice Divide before multiply
    /// @dev Precision loss issue
    function calculateFee(uint256 amount, uint256 feePercent) external pure returns (uint256) {
        return (amount / 100) * feePercent;
    }
    
    /// @notice Strict balance check
    /// @dev Can be broken by forced ETH sends
    function checkBalance() external view returns (bool) {
        return address(this).balance == 100 ether;
    }
    
    /// @notice Use block timestamp for randomness
    /// @dev Weak randomness source
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp)));
    }
    
    /// @notice Mint tokens
    /// @dev Internal mint function exposed
    function _mint(address to, uint256 amount) internal {
        // Minting logic
    }
    
    /// @notice Renounce ownership
    /// @dev Sets owner to zero address
    function renounceOwnership() public onlyOwner {
        owner = address(0);
    }
    
    /// @notice Set fee percentage
    /// @dev No upper bound check
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
    
    uint256 public fee;
    address public owner;
}
'''


@pytest.fixture
def sample_solana_contract():
    """A small Anchor/Rust contract string for testing."""
    return '''
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vault {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        Ok(())
    }
    
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        
        token::transfer(cpi_ctx, amount)?;
        
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits += amount;
        
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        
        let vault = &ctx.accounts.vault;
        let seeds = &[
            b"vault".as_ref(),
            vault.authority.as_ref(),
            &[vault.bump],
        ];
        let signer = &[&seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        
        token::transfer(cpi_ctx, amount)?;
        
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits -= amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + Vault::SIZE)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub bump: u8,
}

impl Vault {
    pub const SIZE: usize = 32 + 8 + 1;
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
'''


@pytest.fixture
def sample_config():
    """A valid garrison.toml config dict."""
    return {
        "engine": {
            "name": "Garrison Security Engine",
            "version": "3.4.0",
            "fail_on_severity": "HIGH",
            "max_findings": 100
        },
        "heuristics": {
            "enabled": True,
            "severity_overrides": {
                "TX_ORIGIN_USAGE": "CRITICAL"
            },
            "disabled_rules": {
                "HARDCODED_ADDRESS": True
            }
        },
        "suppressions": [
            {
                "rule_id": "TX_ORIGIN_USAGE",
                "file": "test/MockContract.sol",
                "line": 42,
                "reason": "Test file, intentional usage"
            },
            {
                "rule_id": "BLOCK_TIMESTAMP_RANDOMNESS",
                "reason": "Accepted risk for this project"
            }
        ],
        "static_analysis": {
            "slither": {
                "enabled": True,
                "exclude_detectors": "solc-version,naming-convention",
                "include_impact": "High,Medium"
            },
            "aderyn": {
                "enabled": False,
                "scope": ""
            }
        },
        "fuzzing": {
            "foundry": {
                "enabled": False,
                "runs": 10000,
                "max_test_rejects": 100000
            },
            "medusa": {
                "enabled": False,
                "test_limit": 100000,
                "timeout": 300,
                "workers": 10
            }
        },
        "chains": {
            "solana": {
                "enabled": False,
                "project_root": "./programs"
            },
            "evm": {
                "solc_version": ">=0.8.0",
                "trusted_contracts": []
            }
        },
        "reporting": {
            "format": "markdown",
            "sections": {
                "executive_summary": True,
                "supply_chain": True,
                "static_analysis": True,
                "heuristic_scan": True,
                "fuzzing": False,
                "threat_intel": False,
                "access_matrix": True
            },
            "verbosity": "standard",
            "group_by": "severity"
        },
        "ci": {
            "fail_on_findings": True,
            "post_pr_comment": True,
            "upload_sarif": False,
            "exclude_paths": ["test/**", "script/**", "node_modules/**"]
        }
    }


@pytest.fixture
def tmp_contract_file(tmp_path):
    """Fixture that writes a sample contract to a temp file and yields the path."""
    def _create_contract(content, filename="TestContract.sol"):
        contract_file = tmp_path / filename
        contract_file.write_text(content)
        return str(contract_file)
    return _create_contract


# =============================================================================
# Mock Output Fixtures
# =============================================================================

@pytest.fixture
def mock_slither_output():
    """Realistic Slither JSON output dict."""
    return {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy in VulnerableVault.withdraw (Vault.sol#45-52)",
                    "type": "function",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {
                                "filename_short": "Vault.sol",
                                "lines": [45, 46, 47, 48, 49, 50, 51, 52]
                            }
                        }
                    ]
                },
                {
                    "check": "tx-origin",
                    "impact": "Medium",
                    "confidence": "High",
                    "description": "Dangerous usage of tx.origin in VulnerableVault.setAdmin",
                    "type": "function",
                    "elements": [
                        {
                            "type": "function",
                            "name": "setAdmin",
                            "source_mapping": {
                                "filename_short": "Vault.sol",
                                "lines": [65]
                            }
                        }
                    ]
                },
                {
                    "check": "unchecked-transfer",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Unchecked transfer in VulnerableVault.drain",
                    "type": "function",
                    "elements": [
                        {
                            "type": "function",
                            "name": "drain",
                            "source_mapping": {
                                "filename_short": "Vault.sol",
                                "lines": [58]
                            }
                        }
                    ]
                }
            ],
            "errors": []
        },
        "analysis": {
            "contracts": ["VulnerableVault"],
            "files": ["Vault.sol"]
        }
    }


@pytest.fixture
def mock_aderyn_output():
    """Realistic Aderyn JSON output dict."""
    return {
        "total": 5,
        "high": [
            {
                "title": "Reentrancy detected in withdraw function",
                "detector_name": "reentrancy",
                "description": "External call before state update",
                "file": "Vault.sol",
                "line": 45
            },
            {
                "title": "Unchecked low-level call",
                "detector_name": "unchecked-low-level-call",
                "description": "Return value not checked",
                "file": "Vault.sol",
                "line": 75
            }
        ],
        "low": [
            {
                "title": "Unused local variable",
                "detector_name": "unused-var",
                "description": "Variable declared but never used",
                "file": "Vault.sol",
                "line": 30
            }
        ],
        "nc": [
            {
                "title": "Code style issue",
                "detector_name": "code-style",
                "description": "Consider using custom errors",
                "file": "Vault.sol",
                "line": 25
            }
        ]
    }


@pytest.fixture
def mock_osv_response():
    """Mock OSV API response for supply chain testing."""
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "summary": "Critical vulnerability in example-lib",
                "details": "A detailed description of the vulnerability...",
                "aliases": ["CVE-2023-12345"],
                "modified": "2023-06-01T00:00:00Z",
                "published": "2023-05-01T00:00:00Z",
                "database_specific": {
                    "severity": "CRITICAL",
                    "cwe_ids": ["CWE-123"]
                },
                "affected": [
                    {
                        "package": {
                            "name": "example-lib",
                            "ecosystem": "npm"
                        },
                        "versions": ["1.0.0", "1.0.1"]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def mock_empty_osv_response():
    """Empty OSV API response (no vulnerabilities)."""
    return {"vulns": []}


# =============================================================================
# Helper Fixtures
# =============================================================================

@pytest.fixture
def temp_directory(tmp_path):
    """Create a temporary directory for file-based tests."""
    return tmp_path


@pytest.fixture
def sample_old_contract():
    """Old contract version for upgrade diff testing."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UpgradeableToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balances[to] += amount;
    }
    
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
'''


@pytest.fixture
def sample_new_contract_safe():
    """New contract version with safe changes."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UpgradeableToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public newFeature;  // New variable at the end
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balances[to] += amount;
    }
    
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    function newFunction() external view returns (uint256) {
        return newFeature;
    }
}
'''


@pytest.fixture
def sample_new_contract_unsafe():
    """New contract version with unsafe changes (storage collision)."""
    return '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UpgradeableToken {
    uint256 public newFeature;  // Inserted at beginning - DANGEROUS!
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    address public owner;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function mint(address to, uint256 amount) external {
        // Removed onlyOwner modifier - DANGEROUS!
        totalSupply += amount;
        balances[to] += amount;
    }
    
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
'''


# =============================================================================
# Configuration File Fixtures
# =============================================================================

@pytest.fixture
def sample_garrison_toml():
    """Sample garrison.toml content."""
    return """
[engine]
name = "Garrison Security Engine"
version = "3.4.0"
fail_on_severity = "HIGH"
max_findings = 100

[heuristics]
enabled = true

[heuristics.severity_overrides]
TX_ORIGIN_USAGE = "CRITICAL"

[heuristics.disabled_rules]
HARDCODED_ADDRESS = true

[[suppressions]]
rule_id = "TX_ORIGIN_USAGE"
file = "test/MockContract.sol"
line = 42
reason = "Test file, intentional usage"

[[suppressions]]
rule_id = "BLOCK_TIMESTAMP_RANDOMNESS"
reason = "Accepted risk for this project"

[static_analysis.slither]
enabled = true
exclude_detectors = "solc-version,naming-convention"
include_impact = "High,Medium"

[static_analysis.aderyn]
enabled = false

[fuzzing.foundry]
enabled = false
runs = 10000

[fuzzing.medusa]
enabled = false
test_limit = 100000

[reporting]
format = "markdown"
verbosity = "standard"
group_by = "severity"

[reporting.sections]
executive_summary = true
static_analysis = true
heuristic_scan = true
"""


@pytest.fixture
def audit_profile_toml():
    """Audit profile configuration."""
    return """
[engine]
fail_on_severity = "MEDIUM"
max_findings = 0

[heuristics]
enabled = true

[static_analysis.slither]
enabled = true
include_impact = "High,Medium,Low"

[reporting]
format = "html"
verbosity = "verbose"
"""


@pytest.fixture
def pr_profile_toml():
    """PR profile configuration."""
    return """
[engine]
fail_on_severity = "HIGH"
max_findings = 50

[heuristics]
enabled = true

[ci]
fail_on_findings = true
post_pr_comment = true
upload_sarif = true
"""


@pytest.fixture
def bounty_profile_toml():
    """Bug bounty profile configuration."""
    return """
[engine]
fail_on_severity = "INFO"
max_findings = 0

[heuristics]
enabled = true

[static_analysis.slither]
enabled = true
include_impact = "High,Medium,Low"

[static_analysis.aderyn]
enabled = true

[fuzzing.foundry]
enabled = true
runs = 100000

[reporting]
format = "sarif"
verbosity = "verbose"
"""


# =============================================================================
# RAG Engine Fixtures
# =============================================================================

@pytest.fixture
def sample_idl_json():
    """A minimal valid Anchor IDL JSON dict."""
    return {
        "name": "test_program",
        "version": "0.1.0",
        "instructions": [
            {
                "name": "initialize",
                "accounts": [
                    {
                        "name": "vault",
                        "isMut": True,
                        "isSigner": False,
                        "pda": {
                            "seeds": [
                                {"kind": "const", "value": [118, 97, 117, 108, 116]},
                                {"kind": "account", "path": "authority"}
                            ]
                        }
                    },
                    {
                        "name": "authority",
                        "isMut": True,
                        "isSigner": True
                    },
                    {
                        "name": "system_program",
                        "isMut": False,
                        "isSigner": False
                    }
                ],
                "args": []
            },
            {
                "name": "deposit",
                "accounts": [
                    {
                        "name": "vault",
                        "isMut": True,
                        "isSigner": False
                    },
                    {
                        "name": "authority",
                        "isMut": False,
                        "isSigner": True
                    }
                ],
                "args": [
                    {"name": "amount", "type": "u64"}
                ]
            }
        ],
        "accounts": [
            {
                "name": "Vault",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "authority", "type": "publicKey"},
                        {"name": "total_deposits", "type": "u64"}
                    ]
                }
            }
        ],
        "types": [],
        "events": [
            {
                "name": "DepositEvent",
                "fields": [
                    {"name": "amount", "type": "u64", "index": False}
                ]
            }
        ],
        "errors": [
            {
                "code": 6000,
                "name": "InvalidAmount",
                "msg": "Invalid amount"
            }
        ],
        "metadata": {
            "address": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"
        }
    }


@pytest.fixture
def sample_git_log():
    """Mock git log output string."""
    return """abc123def456789012345678901234567890abcd|John Doe|john@example.com|2024-01-15T10:30:00+00:00|Initial commit

contracts/Vault.sol
contracts/Token.sol
<<COMMIT_SEP>>
def789abc0123456789012345678901234567890ab|Jane Smith|jane@example.com|2024-01-16T14:45:00+00:00|Add deposit function

contracts/Vault.sol
<<COMMIT_SEP>>
1234567890abcdef1234567890abcdef12345678|Bob Wilson|bob@example.com|2024-01-17T09:00:00+00:00|Fix reentrancy bug

contracts/Vault.sol
contracts/utils/Math.sol
<<COMMIT_SEP>>"""


@pytest.fixture
def sample_attack_graph_data():
    """Sample graph JSON for visualizer tests."""
    return {
        "nodes": [
            {
                "id": "Contract_Vault_1234",
                "type": "Contract",
                "name": "Vault",
                "size": 15,
                "file": "contracts/Vault.sol",
                "line": 1
            },
            {
                "id": "Function_withdraw_1234_L45",
                "type": "Function",
                "name": "withdraw",
                "size": 12,
                "file": "contracts/Vault.sol",
                "line": 45,
                "visibility": "public"
            },
            {
                "id": "Vulnerability_REENTRANCY_1234_L50",
                "type": "Vulnerability",
                "name": "REENTRANCY",
                "size": 20,
                "severity": "CRITICAL",
                "file": "contracts/Vault.sol",
                "line": 50,
                "rule_id": "REENTRANCY",
                "description": "Reentrancy vulnerability detected"
            },
            {
                "id": "ExternalCall_recipient_call_1234_L52",
                "type": "ExternalCall",
                "name": "recipient.call{value: amount}()",
                "size": 10,
                "file": "contracts/Vault.sol",
                "line": 52
            },
            {
                "id": "Function_deposit_1234_L30",
                "type": "Function",
                "name": "deposit",
                "size": 12,
                "file": "contracts/Vault.sol",
                "line": 30,
                "visibility": "external"
            }
        ],
        "links": [
            {
                "source": "Contract_Vault_1234",
                "target": "Function_withdraw_1234_L45",
                "type": "contains"
            },
            {
                "source": "Contract_Vault_1234",
                "target": "Function_deposit_1234_L30",
                "type": "contains"
            },
            {
                "source": "Function_withdraw_1234_L45",
                "target": "ExternalCall_recipient_call_1234_L52",
                "type": "calls"
            },
            {
                "source": "Function_withdraw_1234_L45",
                "target": "Vulnerability_REENTRANCY_1234_L50",
                "type": "triggers"
            }
        ],
        "metadata": {
            "node_count": 5,
            "edge_count": 4,
            "node_types": ["Contract", "Function", "Vulnerability", "ExternalCall"],
            "edge_types": ["contains", "calls", "triggers"]
        }
    }


@pytest.fixture
def sample_embeddings():
    """List of mock embedding vectors (simple float lists, dimension 384)."""
    import math
    
    def create_mock_embedding(seed, dim=384):
        """Create a deterministic mock embedding vector."""
        # Use a simple pattern to create consistent vectors
        vector = []
        for i in range(dim):
            # Create a pattern based on seed and position
            val = math.sin((seed + i) * 0.1) * 0.5 + 0.5
            vector.append(round(val, 6))
        return vector
    
    return {
        "reentrancy": create_mock_embedding(1),
        "access_control": create_mock_embedding(2),
        "overflow": create_mock_embedding(3),
        "oracle": create_mock_embedding(4),
        "flash_loan": create_mock_embedding(5),
        "similar_to_reentrancy": create_mock_embedding(1.1),  # Very similar to reentrancy
    }
