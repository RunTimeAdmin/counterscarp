"""Protocol fingerprint database for similarity scanning.

This module provides a database of known protocol fingerprints that can be
used to identify similar contracts and assess inherited vulnerabilities.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import CounterscarpConfigError, CounterscarpValidationError
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None
    CounterscarpConfigError = None
    CounterscarpValidationError = None

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class ProtocolFingerprint:
    """Represents a known protocol fingerprint for similarity detection.

    Attributes:
        name: Human-readable protocol name (e.g., "Uniswap V2").
        category: Protocol category (AMM, Lending, Stablecoin, etc.).
        version: Protocol version string (e.g., "2.0").
        function_signatures: List of characteristic function signatures.
        event_signatures: List of characteristic event signatures.
        storage_patterns: Regex patterns for storage variable identification.
        inheritance_markers: Interface/contract names this protocol implements.
        constants: Known constant values used by the protocol.
        known_vulnerabilities: List of known vulnerabilities with metadata.
    """
    name: str
    category: str
    version: str
    function_signatures: List[str] = field(default_factory=list)
    event_signatures: List[str] = field(default_factory=list)
    storage_patterns: List[str] = field(default_factory=list)
    inheritance_markers: List[str] = field(default_factory=list)
    constants: Dict[str, str] = field(default_factory=dict)
    known_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert fingerprint to dictionary for serialization.

        Returns:
            Dictionary representation of the fingerprint.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolFingerprint":
        """Create fingerprint from dictionary.

        Args:
            data: Dictionary containing fingerprint data.

        Returns:
            ProtocolFingerprint instance.
        """
        return cls(
            name=data.get("name", ""),
            category=data.get("category", ""),
            version=data.get("version", ""),
            function_signatures=data.get("function_signatures", []),
            event_signatures=data.get("event_signatures", []),
            storage_patterns=data.get("storage_patterns", []),
            inheritance_markers=data.get("inheritance_markers", []),
            constants=data.get("constants", {}),
            known_vulnerabilities=data.get("known_vulnerabilities", []),
        )


# Path to the bundled JSON fingerprint database (relative to this file)
_FINGERPRINT_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "protocol_fingerprints.json")


def _load_fingerprints_from_json(path: str) -> Optional[List[ProtocolFingerprint]]:
    """Attempt to load fingerprints from the JSON database file.

    Args:
        path: Path to the JSON file.

    Returns:
        List of ProtocolFingerprint instances on success, None on failure.
    """
    if not os.path.isfile(path):
        logger.warning(f"Fingerprint JSON database not found at {path}; falling back to hardcoded entries")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        fingerprints = [ProtocolFingerprint.from_dict(item) for item in data]
        logger.debug(f"Loaded {len(fingerprints)} protocol fingerprints from {path}")
        return fingerprints
    except (IOError, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.warning(f"Failed to load fingerprint JSON database from {path}: {exc}; falling back to hardcoded entries")
        return None


def get_default_fingerprints() -> List[ProtocolFingerprint]:
    """Get all built-in protocol fingerprints.

    Attempts to load from the bundled JSON database first
    (``data/protocol_fingerprints.json``).  Falls back to the hardcoded
    list if the file is missing or unreadable.

    Returns:
        List of built-in ProtocolFingerprint instances.
    """
    # JSON file is the source of truth — load it when available
    json_fingerprints = _load_fingerprints_from_json(_FINGERPRINT_DB_PATH)
    if json_fingerprints is not None:
        return json_fingerprints

    # ------------------------------------------------------------------ #
    # Hardcoded fallback — kept in sync with data/protocol_fingerprints.json
    # ------------------------------------------------------------------ #
    fingerprints = []

    # Uniswap V2 - AMM
    fingerprints.append(
        ProtocolFingerprint(
            name="Uniswap V2",
            category="AMM",
            version="2.0",
            function_signatures=[
                "swap(uint256,uint256,address,bytes)",
                "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
                "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
                "getReserves()",
                "mint(address)",
                "burn(address)",
                "sync()",
                "skim(address)",
                "initialize(address,address)",
            ],
            event_signatures=[
                "Swap(address indexed sender,uint256 amount0In,uint256 amount1In,uint256 amount0Out,uint256 amount1Out,address indexed to)",
                "Sync(uint112 reserve0,uint112 reserve1)",
                "Mint(address indexed sender,uint256 amount0,uint256 amount1)",
                "Burn(address indexed sender,uint256 amount0,uint256 amount1,address indexed to)",
            ],
            storage_patterns=[
                r"reserve0",
                r"reserve1",
                r"blockTimestampLast",
                r"price0CumulativeLast",
                r"price1CumulativeLast",
                r"kLast",
            ],
            inheritance_markers=[
                "IUniswapV2Pair",
                "IUniswapV2Factory",
                "IUniswapV2Callee",
                "UniswapV2ERC20",
            ],
            constants={
                "MINIMUM_LIQUIDITY": "1000",
                "SELECTOR": "0x6a627842",
            },
            known_vulnerabilities=[
                {
                    "id": "UNI-V2-001",
                    "title": "K Invariant Manipulation",
                    "severity": "HIGH",
                    "description": "Flash loan attacks can manipulate reserves and break K invariant assumptions",
                    "reference_url": "https://docs.uniswap.org/protocol/V2/concepts/advanced-topics/security-considerations",
                },
                {
                    "id": "UNI-V2-002",
                    "title": "Price Oracle Manipulation",
                    "severity": "CRITICAL",
                    "description": "Spot price from reserves can be manipulated in single block",
                    "reference_url": "https://docs.uniswap.org/protocol/V2/concepts/core-concepts/oracles",
                },
                {
                    "id": "UNI-V2-003",
                    "title": "Reentrancy via swap callback",
                    "severity": "MEDIUM",
                    "description": "swap() callback to uniswapV2Call can enable reentrancy",
                    "reference_url": "https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol",
                },
            ],
        )
    )

    # Uniswap V3 - Concentrated AMM
    fingerprints.append(
        ProtocolFingerprint(
            name="Uniswap V3",
            category="AMM",
            version="3.0",
            function_signatures=[
                "mint(address,int24,int24,uint128,bytes)",
                "burn(int24,int24,uint128)",
                "collect(address,int24,int24,uint128,uint128)",
                "swap(address,bool,int256,uint160,bytes)",
                "flash(address,uint256,uint256,bytes)",
                "observe(uint32[])",
                "increaseObservationCardinalityNext(uint16)",
                "initialize(uint160)",
            ],
            event_signatures=[
                "Mint(address indexed sender,address indexed owner,int24 indexed tickLower,int24 tickUpper,uint128 amount,uint256 amount0,uint256 amount1)",
                "Burn(address indexed owner,int24 indexed tickLower,int24 tickUpper,uint128 amount,uint256 amount0,uint256 amount1)",
                "Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)",
                "Flash(address indexed sender,address indexed recipient,uint256 amount0,uint256 amount1,uint256 paid0,uint256 paid1)",
            ],
            storage_patterns=[
                r"slot0",
                r"liquidity",
                r"tickBitmap",
                r"ticks",
                r"positions",
                r"feeGrowthGlobal0X128",
                r"feeGrowthGlobal1X128",
                r"sqrtPriceX96",
            ],
            inheritance_markers=[
                "IUniswapV3Pool",
                "IUniswapV3Factory",
                "IUniswapV3MintCallback",
                "IUniswapV3SwapCallback",
                "IUniswapV3FlashCallback",
            ],
            constants={
                "MIN_TICK": "-887272",
                "MAX_TICK": "887272",
                "TICK_SPACING": "60",
            },
            known_vulnerabilities=[
                {
                    "id": "UNI-V3-001",
                    "title": "Tick Math Precision Loss",
                    "severity": "MEDIUM",
                    "description": "Price calculations at tick boundaries may have precision issues",
                    "reference_url": "https://docs.uniswap.org/protocol/concepts/V3-overview/oracle",
                },
                {
                    "id": "UNI-V3-002",
                    "title": "Flash Loan Price Manipulation",
                    "severity": "HIGH",
                    "description": "Concentrated liquidity makes price manipulation more capital efficient",
                    "reference_url": "https://docs.uniswap.org/protocol/concepts/advanced-topics/security-considerations",
                },
                {
                    "id": "UNI-V3-003",
                    "title": "TWAP Oracle Staleness",
                    "severity": "MEDIUM",
                    "description": "Oracle observations can become stale if not regularly updated",
                    "reference_url": "https://docs.uniswap.org/protocol/concepts/V3-overview/oracle",
                },
            ],
        )
    )

    # Compound V2 - Lending
    fingerprints.append(
        ProtocolFingerprint(
            name="Compound V2",
            category="Lending",
            version="2.0",
            function_signatures=[
                "mint(uint256)",
                "redeem(uint256)",
                "redeemUnderlying(uint256)",
                "borrow(uint256)",
                "repayBorrow(uint256)",
                "repayBorrowBehalf(address,uint256)",
                "liquidateBorrow(address,address,uint256)",
                "accrueInterest()",
                "exchangeRateCurrent()",
                "borrowBalanceCurrent(address)",
                "getAccountLiquidity(address)",
            ],
            event_signatures=[
                "Mint(address,uint256,uint256)",
                "Redeem(address,uint256,uint256)",
                "Borrow(address,uint256,uint256,uint256)",
                "RepayBorrow(address,address,uint256,uint256,uint256)",
                "LiquidateBorrow(address,address,uint256,uint256,address)",
                "AccrueInterest(uint256,uint256,uint256,uint256)",
            ],
            storage_patterns=[
                r"accountBorrows",
                r"accountTokens",
                r"borrowIndex",
                r"totalBorrows",
                r"totalReserves",
                r"accrualBlockNumber",
                r"borrowRatePerBlock",
                r"supplyRatePerBlock",
                r"exchangeRateStored",
            ],
            inheritance_markers=[
                "CToken",
                "CErc20",
                "CEther",
                "Comptroller",
                "ComptrollerInterface",
                "InterestRateModel",
            ],
            constants={
                "collateralFactor": "0.75",
                "reserveFactor": "0.05",
                "closeFactor": "0.5",
            },
            known_vulnerabilities=[
                {
                    "id": "COMP-V2-001",
                    "title": "Interest Rate Model Manipulation",
                    "severity": "HIGH",
                    "description": "Flash loans can temporarily manipulate utilization and interest rates",
                    "reference_url": "https://compound.finance/docs/security",
                },
                {
                    "id": "COMP-V2-002",
                    "title": "Price Oracle Dependency",
                    "severity": "CRITICAL",
                    "description": "Single price oracle failure can lead to mass liquidations",
                    "reference_url": "https://compound.finance/docs/prices",
                },
                {
                    "id": "COMP-V2-003",
                    "title": "Reentrancy on CEther",
                    "severity": "MEDIUM",
                    "description": "ETH transfers in mint/redeem can enable reentrancy",
                    "reference_url": "https://github.com/compound-finance/compound-protocol",
                },
            ],
        )
    )

    # Aave V2/V3 - Lending
    fingerprints.append(
        ProtocolFingerprint(
            name="Aave V2/V3",
            category="Lending",
            version="3.0",
            function_signatures=[
                "deposit(address,uint256,address,uint16)",
                "withdraw(address,uint256,address)",
                "borrow(address,uint256,uint256,uint16,address)",
                "repay(address,uint256,uint256,address)",
                "flashLoan(address[],uint256[],uint256[],address,bytes)",
                "flashLoanSimple(address,uint256,bytes)",
                "liquidationCall(address,address,address,uint256,bool)",
                "setUserUseReserveAsCollateral(address,bool)",
                "swapBorrowRateMode(address,uint256)",
                "rebalanceStableBorrowRate(address,address)",
            ],
            event_signatures=[
                "Deposit(address indexed reserve,address user,address indexed onBehalfOf,uint256 amount,uint16 indexed referral)",
                "Withdraw(address indexed reserve,address indexed user,address indexed to,uint256 amount)",
                "Borrow(address indexed reserve,address user,address indexed onBehalfOf,uint256 amount,uint256 borrowRateMode,uint256 borrowRate,uint16 indexed referral)",
                "Repay(address indexed reserve,address indexed user,address indexed repayer,uint256 amount)",
                "FlashLoan(address indexed target,address initiator,address indexed asset,uint256 amount,uint256 premium,uint16 indexed referralCode)",
                "LiquidationCall(address indexed collateralAsset,address indexed debtAsset,address indexed user,uint256 debtToCover,uint256 liquidatedCollateralAmount,address liquidator,bool receiveAToken)",
            ],
            storage_patterns=[
                r"_reserves",
                r"_usersConfig",
                r"_reservesList",
                r"_eModeCategories",
                r"_flashLoanPremiumTotal",
                r"_flashLoanPremiumToProtocol",
                r"_maxStableRateBorrowSizePercent",
                r"_reservesCount",
            ],
            inheritance_markers=[
                "IPool",
                "IPoolAddressesProvider",
                "IAaveIncentivesController",
                "IAToken",
                "IVariableDebtToken",
                "IStableDebtToken",
                "FlashLoanSimpleReceiverBase",
            ],
            constants={
                "FLASHLOAN_PREMIUM_TOTAL": "9",
                "FLASHLOAN_PREMIUM_TO_PROTOCOL": "0",
                "MAX_STABLE_RATE_BORROW_SIZE_PERCENT": "2500",
            },
            known_vulnerabilities=[
                {
                    "id": "AAVE-001",
                    "title": "Flash Loan Attack Vectors",
                    "severity": "HIGH",
                    "description": "Flash loans can be used to manipulate governance, prices, and liquidations",
                    "reference_url": "https://docs.aave.com/developers/guides/flash-loans",
                },
                {
                    "id": "AAVE-002",
                    "title": "Price Oracle Manipulation",
                    "severity": "CRITICAL",
                    "description": "Aave relies on Chainlink oracles which can be manipulated in extreme conditions",
                    "reference_url": "https://docs.aave.com/developers/guides/oracles",
                },
                {
                    "id": "AAVE-003",
                    "title": "Liquidation Bonus Gaming",
                    "severity": "MEDIUM",
                    "description": "Liquidators can optimize bonus extraction through sandwich attacks",
                    "reference_url": "https://docs.aave.com/developers/guides/liquidations",
                },
                {
                    "id": "AAVE-004",
                    "title": "Isolation Mode Bypass",
                    "severity": "HIGH",
                    "description": "V3 isolation mode may have edge cases for debt ceiling enforcement",
                    "reference_url": "https://docs.aave.com/developers/whats-new/isolation-mode",
                },
            ],
        )
    )

    # OpenZeppelin - Access Control
    fingerprints.append(
        ProtocolFingerprint(
            name="OpenZeppelin",
            category="AccessControl",
            version="4.x",
            function_signatures=[
                "owner()",
                "transferOwnership(address)",
                "renounceOwnership()",
                "grantRole(bytes32,address)",
                "revokeRole(bytes32,address)",
                "renounceRole(bytes32,address)",
                "hasRole(bytes32,address)",
                "getRoleAdmin(bytes32)",
                "upgradeTo(address)",
                "upgradeToAndCall(address,bytes)",
            ],
            event_signatures=[
                "OwnershipTransferred(address indexed previousOwner,address indexed newOwner)",
                "RoleGranted(bytes32 indexed role,address indexed account,address indexed sender)",
                "RoleRevoked(bytes32 indexed role,address indexed account,address indexed sender)",
                "RoleAdminChanged(bytes32 indexed role,bytes32 indexed previousAdminRole,bytes32 indexed newAdminRole)",
                "Upgraded(address indexed implementation)",
            ],
            storage_patterns=[
                r"_owner",
                r"_roles",
                r"_initialized",
                r"_initializing",
                r"__gap",
                r"_status",
            ],
            inheritance_markers=[
                "Ownable",
                "AccessControl",
                "AccessControlEnumerable",
                "Initializable",
                "UUPSUpgradeable",
                "TransparentUpgradeableProxy",
                "ERC1967Proxy",
                "ReentrancyGuard",
                "Pausable",
            ],
            constants={
                "DEFAULT_ADMIN_ROLE": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            known_vulnerabilities=[
                {
                    "id": "OZ-001",
                    "title": "Proxy Storage Collision",
                    "severity": "CRITICAL",
                    "description": "Upgradeable proxies can have storage layout collisions between versions",
                    "reference_url": "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
                },
                {
                    "id": "OZ-002",
                    "title": "Initializer Front-running",
                    "severity": "HIGH",
                    "description": "Initializers can be called by anyone before intended deployer",
                    "reference_url": "https://docs.openzeppelin.com/contracts/4.x/api/proxy",
                },
                {
                    "id": "OZ-003",
                    "title": "UUPS Implementation Self-Destruct",
                    "severity": "CRITICAL",
                    "description": "UUPS proxy implementation can be self-destructed, bricking the proxy",
                    "reference_url": "https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable",
                },
                {
                    "id": "OZ-004",
                    "title": "Access Control Bypass via delegatecall",
                    "severity": "HIGH",
                    "description": "Improper use of delegatecall can bypass access control checks",
                    "reference_url": "https://docs.openzeppelin.com/contracts/4.x/api/access",
                },
            ],
        )
    )

    # Curve - Stableswap
    fingerprints.append(
        ProtocolFingerprint(
            name="Curve",
            category="Stableswap",
            version="1.0",
            function_signatures=[
                "exchange(int128,int128,uint256,uint256)",
                "exchange_underlying(int128,int128,uint256,uint256)",
                "add_liquidity(uint256[],uint256)",
                "remove_liquidity(uint256,uint256[])",
                "remove_liquidity_imbalance(uint256[],uint256)",
                "remove_liquidity_one_coin(uint256,int128,uint256)",
                "get_dy(int128,int128,uint256)",
                "get_dy_underlying(int128,int128,uint256)",
                "calc_token_amount(uint256[],bool)",
                "calc_withdraw_one_coin(uint256,int128)",
            ],
            event_signatures=[
                "TokenExchange(address indexed buyer,int128 sold_id,uint256 tokens_sold,int128 bought_id,uint256 tokens_bought)",
                "AddLiquidity(address indexed provider,uint256[] token_amounts,uint256[] fees,uint256 invariant,uint256 token_supply)",
                "RemoveLiquidity(address indexed provider,uint256[] token_amounts,uint256[] fees,uint256 token_supply)",
                "RemoveLiquidityOne(address indexed provider,uint256 token_amount,uint256 coin_index,uint256 coin_amount)",
            ],
            storage_patterns=[
                r"balances",
                r"A",
                r"fee",
                r"admin_fee",
                r"owner",
                r"coins",
                r"underlying_coins",
                r"token",
            ],
            inheritance_markers=[
                "StableSwap",
                "CurvePool",
                "CurveToken",
                "LiquidityGauge",
                "Minter",
            ],
            constants={
                "A_PRECISION": "100",
                "FEE_DENOMINATOR": "10000000000",
                "PRECISION": "1000000000000000000",
            },
            known_vulnerabilities=[
                {
                    "id": "CURVE-001",
                    "title": "Read-only Reentrancy",
                    "severity": "CRITICAL",
                    "description": "get_dy and calc_token_amount can be manipulated during callback",
                    "reference_url": "https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
                },
                {
                    "id": "CURVE-002",
                    "title": "Oracle Manipulation via Flash Loan",
                    "severity": "HIGH",
                    "description": "Price oracles derived from Curve pools can be manipulated",
                    "reference_url": "https://medium.com/@zokyo.io/curve-vulnerability-deep-dive",
                },
                {
                    "id": "CURVE-003",
                    "title": "A Parameter Manipulation",
                    "severity": "MEDIUM",
                    "description": "Amplification parameter changes can cause temporary imbalances",
                    "reference_url": "https://curve.readthedocs.io/dao-governance.html",
                },
            ],
        )
    )

    # MakerDAO - CDP
    fingerprints.append(
        ProtocolFingerprint(
            name="MakerDAO",
            category="CDP",
            version="1.2",
            function_signatures=[
                "frob(bytes32,address,address,address,int256,int256)",
                "drip(bytes32)",
                "file(bytes32,bytes32,uint256)",
                "cage()",
                "cage(bytes32)",
                "join(address,uint256)",
                "exit(address,uint256)",
                "draw(bytes32,uint256)",
                "wipe(bytes32,uint256)",
                "shut(bytes32)",
                "bite(bytes32,address)",
            ],
            event_signatures=[
                "LogNote(bytes4,address,bytes32,bytes32,bytes)",
                "NewCdp(address indexed usr,address indexed own,uint256 indexed cdp)",
                "Frob(bytes32 indexed ilk,address indexed urn,uint256 ink,uint256 art,uint256 dart,int256 dink)",
                "Grab(bytes32 indexed ilk,address indexed urn,address v,address w,int256 dink,int256 dart)",
            ],
            storage_patterns=[
                r"ilks",
                r"urns",
                r"gem",
                r"dai",
                r"sin",
                r"debt",
                r"vice",
                r"Line",
                r"live",
            ],
            inheritance_markers=[
                "Vat",
                "DaiJoin",
                "GemJoin",
                "DSSProxy",
                "CDPManager",
                "Spotter",
                "Jug",
                "Cat",
                "Dog",
                "End",
            ],
            constants={
                "RAY": "1000000000000000000000000000",
                "WAD": "1000000000000000000",
                "RAD": "1000000000000000000000000000000000000000000000",
            },
            known_vulnerabilities=[
                {
                    "id": "MAKER-001",
                    "title": "Liquidation Auction Gaming",
                    "severity": "HIGH",
                    "description": "Keepers can manipulate auction timing for better prices",
                    "reference_url": "https://makerdao.com/en/whitepaper",
                },
                {
                    "id": "MAKER-002",
                    "title": "Oracle Delay Exploitation",
                    "severity": "CRITICAL",
                    "description": "OSM delay can be exploited during rapid price movements",
                    "reference_url": "https://docs.makerdao.com/smart-contract-modules/oracle-module",
                },
                {
                    "id": "MAKER-003",
                    "title": "Emergency Shutdown Edge Cases",
                    "severity": "MEDIUM",
                    "description": "Cage mode may have edge cases for collateral redemption",
                    "reference_url": "https://docs.makerdao.com/smart-contract-modules/shutdown-module",
                },
            ],
        )
    )

    logger.debug(f"Loaded {len(fingerprints)} default protocol fingerprints")
    return fingerprints


def save_fingerprint_db(fingerprints: List[ProtocolFingerprint], path: str) -> None:
    """Serialize fingerprints to JSON file.

    Args:
        fingerprints: List of ProtocolFingerprint instances to save.
        path: Path to the output JSON file.

    Raises:
        CounterscarpConfigError: If file cannot be written.
    """
    try:
        data = [fp.to_dict() for fp in fingerprints]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(fingerprints)} fingerprints to {path}")
    except (IOError, OSError) as e:
        error_msg = f"Failed to save fingerprint database to {path}"
        logger.error(error_msg)
        if CounterscarpConfigError:
            raise CounterscarpConfigError(error_msg, details={"path": path, "error": str(e)})
        raise


def load_fingerprint_db(path: str) -> List[ProtocolFingerprint]:
    """Deserialize fingerprints from JSON file.

    Args:
        path: Path to the JSON file to load.

    Returns:
        List of ProtocolFingerprint instances.

    Raises:
        CounterscarpConfigError: If file cannot be read or parsed.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        fingerprints = [ProtocolFingerprint.from_dict(item) for item in data]
        logger.info(f"Loaded {len(fingerprints)} fingerprints from {path}")
        return fingerprints
    except (IOError, OSError) as e:
        error_msg = f"Failed to load fingerprint database from {path}"
        logger.error(error_msg)
        if CounterscarpConfigError:
            raise CounterscarpConfigError(error_msg, details={"path": path, "error": str(e)})
        raise
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON in fingerprint database: {path}"
        logger.error(error_msg)
        if CounterscarpConfigError:
            raise CounterscarpConfigError(error_msg, details={"path": path, "error": str(e)})
        raise


def get_fingerprint_by_name(
    name: str, fingerprints: Optional[List[ProtocolFingerprint]] = None
) -> Optional[ProtocolFingerprint]:
    """Get a fingerprint by protocol name.

    Args:
        name: Name of the protocol to find.
        fingerprints: Optional list to search. Uses defaults if None.

    Returns:
        ProtocolFingerprint if found, None otherwise.
    """
    if fingerprints is None:
        fingerprints = get_default_fingerprints()

    for fp in fingerprints:
        if fp.name.lower() == name.lower():
            return fp
    return None


def load_community_signatures(community_dir: str = None) -> List[ProtocolFingerprint]:
    """Load community-contributed protocol signatures from data/community_signatures/*.json

    Args:
        community_dir: Path to the community signatures directory.
            Defaults to ``data/community_signatures/`` relative to this file.

    Returns:
        List of ProtocolFingerprint instances loaded from community files.
    """
    if community_dir is None:
        community_dir = os.path.join(os.path.dirname(__file__), "data", "community_signatures")

    signatures = []
    if not os.path.isdir(community_dir):
        return signatures

    for json_file in sorted(Path(community_dir).glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Validate required fields
            required = ["name", "category", "function_signatures"]
            if not all(k in data for k in required):
                logger.warning(f"Skipping {json_file.name}: missing required fields {required}")
                continue
            sig = ProtocolFingerprint.from_dict(data)
            signatures.append(sig)
            logger.info(f"Loaded community signature: {sig.name} ({json_file.name})")
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to load {json_file.name}: {e}")

    return signatures


def get_fingerprints_by_category(
    category: str, fingerprints: Optional[List[ProtocolFingerprint]] = None
) -> List[ProtocolFingerprint]:
    """Get all fingerprints in a category.

    Args:
        category: Category to filter by.
        fingerprints: Optional list to filter. Uses defaults if None.

    Returns:
        List of matching ProtocolFingerprints.
    """
    if fingerprints is None:
        fingerprints = get_default_fingerprints()

    return [fp for fp in fingerprints if fp.category.lower() == category.lower()]


if __name__ == "__main__":
    # Test code
    print("Testing Protocol Database\n")

    # Get default fingerprints
    fps = get_default_fingerprints()
    print(f"Loaded {len(fps)} default fingerprints:")
    for fp in fps:
        print(f"  - {fp.name} ({fp.category}) v{fp.version}")
        print(f"    Functions: {len(fp.function_signatures)}")
        print(f"    Events: {len(fp.event_signatures)}")
        print(f"    Known Vulnerabilities: {len(fp.known_vulnerabilities)}")
        print()

    # Test save/load
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        test_path = os.path.join(tmpdir, "test_fingerprints.json")
        save_fingerprint_db(fps, test_path)
        loaded = load_fingerprint_db(test_path)
        print(f"Save/Load test: {len(loaded)} fingerprints")

    # Test lookup
    uni = get_fingerprint_by_name("Uniswap V2")
    if uni:
        print(f"\nFound: {uni.name}")
        print(f"  Category: {uni.category}")
        print(f"  Vulnerabilities:")
        for vuln in uni.known_vulnerabilities:
            print(f"    - [{vuln['severity']}] {vuln['title']}")
