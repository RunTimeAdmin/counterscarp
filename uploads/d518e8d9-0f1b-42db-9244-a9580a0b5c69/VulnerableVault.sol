// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19; // FLOATING_PRAGMA: caret allows any 0.8.x patch

import "./TokenHelper.sol";

/**
 * @title VulnerableVault
 * @dev  INTENTIONALLY VULNERABLE — FOR HEURISTIC SCANNER TESTING ONLY.
 *       This contract contains ~25 known vulnerability patterns that
 *       the Sentinel heuristic_scanner should flag.  DO NOT DEPLOY.
 */

// ── Minimal interfaces so the file compiles standalone ──────────────

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IChainlink {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

// ── Main Contract ───────────────────────────────────────────────────

contract VulnerableVault {

    // ── State ────────────────────────────────────────────────────
    address public owner;
    ITokenHelper public token;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public depositTime;
    address[] public depositors;

    bool tradingEnabled;                    // TRADING_TOGGLE_BOOL: bool tradingEnabled
    uint256 public feeRate;               // target of SET_FEE_FUNCTION
    uint256 public totalDeposits;

    // STORAGE_COLLISION_RISK: UUPS / initializer / __gap patterns
    address public implementation;
    uint256[49] private __gap;

    // HARDCODED_ADDRESS: 40-hex-char literal
    address public constant TREASURY =
        0x00000000219ab540356cBB839Cbe05303d7705Fa;

    // ── Constructor (missing zero-address check on _token) ──────
    constructor(address _token) {
        owner = msg.sender;
        token = ITokenHelper(_token);
        // VULN: no require(_token != address(0))
    }

    // ── Deposit — front-running vulnerable, no commit-reveal ────
    // Missing event emission on state change
    function deposit() external payable {
        require(tradingEnabled, "Trading paused");
        balances[msg.sender] += msg.value;
        depositTime[msg.sender] = block.timestamp; // BLOCK_TIMESTAMP_RANDOMNESS
        totalDeposits += msg.value;
        // Missing: emit Deposited(msg.sender, msg.value)
    }

    // ── Withdraw — classic reentrancy (call before state update) ─
    // UNCHECKED_EXTERNAL_CALL: .call{} return value ignored
    function withdraw(uint256 amount) external {
        // Reentrancy: external call BEFORE state update
        (bool sent, ) = msg.sender.call{value: amount}("");
        // sent is captured but never checked — effectively unchecked
        // State update AFTER call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        // Missing event
    }

    // ── EMERGENCY_WITHDRAW_PUBLIC — no access control on name ───
    function emergencyWithdraw() external {
        uint256 bal = balances[msg.sender];
        // UNCHECKED_EXTERNAL_CALL: .call{} without return check
        msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
        // Missing event
    }

    // ── drain() also matches EMERGENCY_WITHDRAW_PUBLIC ──────────
    function drain() external {
        uint256 bal = balances[msg.sender];
        // transfer() with hardcoded 2300 gas stipend
        payable(msg.sender).transfer(bal);
        balances[msg.sender] = 0;
    }

    // ── TX_ORIGIN_USAGE + UPGRADE_FUNCTION ──────────────────────
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner"); // TX_ORIGIN_USAGE
        owner = newOwner;
        // Missing event
    }

    // ── DELEGATECALL_USAGE — user-controlled target ─────────────
    function executeDelegate(address target, bytes calldata data) external {
        target.delegatecall(data); // DELEGATECALL_USAGE
    }

    // ── ARBITRARY_EXTERNAL_CALL + LOWLEVEL_CALL_USAGE ───────────
    // Public, address + calldata params, no auth modifier, .call{}(data)
    function executeCall(address target, bytes calldata data) external {
        target.call{value: 0}(data); // ARBITRARY_EXTERNAL_CALL
    }

    // ── LOWLEVEL_CALL_USAGE — plain .call("") ───────────────────
    function rawCall(address target) external {
        target.call(""); // LOWLEVEL_CALL_USAGE: .call(
    }

    // ── BLOCK_TIMESTAMP_RANDOMNESS — pseudo-random eligibility ──
    function isEligibleForReward(address user) external view returns (bool) {
        return (block.timestamp % 100) < 50 && balances[user] > 0;
    }

    // ── Selfdestruct ────────────────────────────────────────────
    function destroy() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }

    // ── SET_FEE_FUNCTION — no upper-bound cap ──────────────────
    function setFee(uint256 newFee) external {
        require(msg.sender == owner);
        feeRate = newFee; // SET_FEE_FUNCTION: no cap check
        // Missing event
    }

    // ── Trading toggle ──────────────────────────────────────────
    function toggleTrading() external {
        require(msg.sender == owner);
        tradingEnabled = !tradingEnabled; // TRADING_TOGGLE_BOOL state
        // Missing event
    }

    // ── STRICT_BALANCE_EQUALITY ─────────────────────────────────
    function isBalanceCorrect() external view returns (bool) {
        return address(this).balance == totalDeposits; // STRICT_BALANCE_EQUALITY
    }

    // ── HIDDEN_MINT — internal _mint() path ────────────────────
    function _creditTokens(address to, uint256 amount) internal {
        _mint(to, amount); // HIDDEN_MINT: _mint() call
    }

    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }

    // ── FAKE_RENOUNCE_OWNER_ZERO ────────────────────────────────
    function renounceOwnership() external {
        require(msg.sender == owner);
        owner = address(0); // FAKE_RENOUNCE_OWNER_ZERO
    }

    // ── DIVIDE_BEFORE_MULTIPLY — precision loss ─────────────────
    function calculateReward(address user) public view returns (uint256) {
        return balances[user] / 100 * feeRate; // DIVIDE_BEFORE_MULTIPLY
    }

    // ── UNSAFE_CAST — downcast without bounds check ─────────────
    function getDepositCount() external view returns (uint64) {
        uint256 len = depositors.length;
        return uint64(len); // UNSAFE_CAST: no bounds check
    }

    // ── Multiple sends in loop + unbounded loop ─────────────────
    function batchDistribute(address[] calldata recipients, uint256 amount) external {
        // Unbounded loop over dynamic array
        for (uint256 i = 0; i < recipients.length; i++) {
            // UNCHECKED_EXTERNAL_CALL: .call{} in loop
            recipients[i].call{value: amount}("");
        }
    }

    // ── MSG_VALUE_LOOP — msg.value in loop condition ────────────
    function depositForMultiple() external payable {
        for (uint256 i = 0; i < msg.value / 1e18; i++) { // MSG_VALUE_LOOP
            balances[msg.sender] += 1e18;
        }
        totalDeposits += msg.value;
    }

    // ── Unbounded loop over dynamic array ───────────────────────
    function processAllDepositors() external {
        for (uint256 i = 0; i < depositors.length; i++) {
            address depositor = depositors[i];
            if (balances[depositor] > 0) {
                depositTime[depositor] = block.timestamp; // BLOCK_TIMESTAMP_RANDOMNESS
            }
        }
    }

    // ── MISSING_SLIPPAGE_PROTECTION — swap with 0 minOut ────────
    function swapTokensForETH(uint256 tokenAmount) external {
        token.swap(tokenAmount, 0, address(this)); // MISSING_SLIPPAGE_PROTECTION: , 0,
    }

    // ── ORACLE_STALENESS_CHECK — Chainlink without staleness ────
    function getChainlinkPrice() external view returns (int256) {
        int256 answer = IChainlink(TREASURY).latestAnswer(); // ORACLE_STALENESS_CHECK
        return answer;
    }

    function getChainlinkPriceV2() external view returns (int256) {
        (, int256 price, , , ) = IChainlink(TREASURY).latestRoundData(); // ORACLE_STALENESS_CHECK
        return price;
    }

    // ── SIGNATURE_REPLAY — ecrecover without nonce/deadline ─────
    function claimWithSignature(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        address signer = ecrecover(ethSignedHash, v, r, s); // SIGNATURE_REPLAY
        require(signer == owner);
        _creditTokens(msg.sender, amount);
    }

    // ── FLASH_LOAN_REENTRANCY — no nonReentrant guard ───────────
    function flashLoan(uint256 amount) external { // FLASH_LOAN_REENTRANCY
        uint256 balanceBefore = address(this).balance;
        // UNCHECKED_EXTERNAL_CALL: .call{} without return check
        msg.sender.call{value: amount}("");
        // DIVIDE_BEFORE_MULTIPLY in fee calc
        require(address(this).balance >= balanceBefore + amount / 100 * feeRate);
    }

    // ── UPGRADE_FUNCTION + STORAGE_COLLISION_RISK ───────────────
    function upgradeTo(address newImpl) external { // UPGRADE_FUNCTION
        require(msg.sender == owner);
        implementation = newImpl; // STORAGE_COLLISION_RISK: UUPS-like
    }

    // ── CENTRALIZATION_RISK — pause/unpause with onlyOwner ──────
    function pause() external onlyOwner { // CENTRALIZATION_RISK
        tradingEnabled = false;
    }

    function unpause() external onlyOwner { // CENTRALIZATION_RISK
        tradingEnabled = true;
    }

    // ── UPGRADE_FUNCTION: setOwner ──────────────────────────────
    function setOwner(address newOwner) external { // UPGRADE_FUNCTION
        require(msg.sender == owner);
        owner = newOwner;
        // Missing event
    }

    // ── Inline assembly ─────────────────────────────────────────
    function getChainId() external view returns (uint256) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return chainId;
    }

    // ── BOOLEAN_TRANSFER_CHECK + UNCHECKED_EXTERNAL_CALL ────────
    function withdrawTokens(address tokenAddr, uint256 amount) external {
        IERC20 t = IERC20(tokenAddr);
        if (!t.transfer(msg.sender, amount)) { // BOOLEAN_TRANSFER_CHECK
            revert("Transfer failed");
        }
    }

    // ── Unchecked ERC20 transferFrom return value ───────────────
    function collectTokens(address tokenAddr, uint256 amount) external {
        IERC20 t = IERC20(tokenAddr);
        t.transferFrom(msg.sender, address(this), amount); // UNCHECKED_EXTERNAL_CALL
    }

    // ── Front-running vulnerable claim ──────────────────────────
    function claimReward() external {
        uint256 reward = calculateReward(msg.sender);
        balances[msg.sender] += reward;
        // Missing event
    }

    // ── STORAGE_COLLISION_RISK: initializer pattern ─────────────
    function initialize(address _token) external {
        owner = msg.sender;
        token = ITokenHelper(_token); // STORAGE_COLLISION_RISK: initializer
    }

    // ── Modifier ────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ── Receive ETH ─────────────────────────────────────────────
    receive() external payable {}
}
