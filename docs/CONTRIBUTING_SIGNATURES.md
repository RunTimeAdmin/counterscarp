# Contributing Protocol Signatures

Protocol signatures are the fingerprints Counterscarp Engine uses to detect when a contract is a fork or close derivative of a known protocol (Uniswap, Aave, Compound, etc.). By matching function selectors, events, storage variable names, and interface markers, the engine can automatically surface inherited vulnerabilities — even when the source is renamed or partially modified.

Adding a new signature means every future scan against that protocol family gets free inherited-risk analysis, benefiting the entire Counterscarp community.

---

## JSON Schema

Each signature file must be a valid JSON object with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | **yes** | Human-readable protocol name, e.g. `"MyDEX V1"` |
| `category` | string | **yes** | One of: `AMM`, `Lending`, `Perpetuals`, `Governance`, `Bridge`, `Other` |
| `version` | string | no | Version string, e.g. `"1.0"` |
| `function_signatures` | string[] | **yes** | Characteristic function signatures in ABI format |
| `event_signatures` | string[] | no | Characteristic event signatures in ABI format |
| `storage_patterns` | string[] | no | Distinctive storage variable names (plain strings or regex) |
| `inheritance_markers` | string[] | no | Interface or base contract names the protocol implements |
| `constants` | object | no | Key/value pairs of notable on-chain constants |
| `known_vulnerabilities` | object[] | no | Documented vulnerability entries (see sub-schema below) |

### Vulnerability sub-schema

```json
{
  "id":          "PROTO-001",
  "title":       "Short descriptive title",
  "severity":    "CRITICAL | HIGH | MEDIUM | LOW",
  "description": "One or two sentences explaining the issue and its impact.",
  "reference_url": "https://link-to-post-mortem-or-docs"
}
```

---

## Contribution Methods

### Method 1 — Local use (instant, no PR needed)

1. Copy `data/protocol_template.json` to `data/community_signatures/my_protocol.json`.
2. Fill in the fields for your protocol.
3. Run a scan — community signatures in that directory are **auto-loaded** on every scan with no code changes required.

```
counterscarp scan ./contracts --fingerprint
```

The loader picks up every `*.json` file in `data/community_signatures/` at startup.

### Method 2 — Upstream contribution (benefits the whole ecosystem)

1. Fork the repository and create a feature branch:
   ```
   git checkout -b feat/signature-my-protocol
   ```
2. Add your completed signature as a new entry in `data/protocol_fingerprints.json` (append to the JSON array).
3. Verify the signature loads cleanly (see **Validation** below).
4. Open a Pull Request with:
   - Title: `feat(signatures): add MyProtocol fingerprint`
   - A brief description of the protocol and any linked CVEs or post-mortems.

---

## Example: Minimal "MyDEX" Signature

```json
{
  "name": "MyDEX",
  "category": "AMM",
  "version": "1.0",
  "function_signatures": [
    "swap(address,uint256,uint256,address)",
    "addLiquidity(address,address,uint256,uint256,address)",
    "removeLiquidity(address,uint256,address)",
    "getPrice(address,address)"
  ],
  "event_signatures": [
    "Swap(address indexed sender,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOut)",
    "LiquidityAdded(address indexed provider,address token0,address token1,uint256 amount0,uint256 amount1)"
  ],
  "storage_patterns": [
    "reserveA",
    "reserveB",
    "feeRate"
  ],
  "inheritance_markers": [
    "IMyDEXPair",
    "IMyDEXFactory"
  ],
  "constants": {
    "FEE_DENOMINATOR": "10000"
  },
  "known_vulnerabilities": [
    {
      "id": "MYDEX-001",
      "title": "Spot Price Oracle Manipulation",
      "severity": "HIGH",
      "description": "Single-block flash loans can skew the reserve ratio used as a price oracle.",
      "reference_url": "https://example.com/mydex-oracle-post-mortem"
    }
  ]
}
```

Save this as `data/community_signatures/mydex.json` and it will be loaded automatically.

---

## Validation

After adding your file, verify it loads and matches as expected:

```bash
# Run fingerprint scan against a known contract
counterscarp scan ./path/to/contract.sol --fingerprint

# Or run the scanner module directly
python fingerprint_scanner.py ./path/to/contract.sol
```

A successful load is confirmed in the log output:

```
INFO  Loaded community signature: MyDEX (mydex.json)
INFO  Loaded 1 community protocol signature(s)
```

If your signature has schema errors, a warning is printed and the file is skipped — other signatures are unaffected.

---

## Tips for Writing Good Signatures

- **Prefer unique function names.** Generic names like `transfer` or `approve` appear in hundreds of contracts and reduce precision. Favour protocol-specific selectors like `flashLoan` or `accrueInterest`.
- **Use distinctive events.** Events are harder to rename during a fork than functions. Include at least 2–3 characteristic events.
- **List inheritance markers.** Interface names (e.g. `IUniswapV2Pair`) are the strongest single signal — include them when known.
- **Document known vulnerabilities.** Even if no CVE exists yet, link to audit reports or community post-mortems. This is the highest-value data for downstream users.
- **Keep `storage_patterns` specific.** Names like `slot0`, `kLast`, or `blockTimestampLast` are far more distinctive than `balance` or `owner`.
- **One protocol per file** when contributing to `community_signatures/` — it makes review and maintenance easier.
