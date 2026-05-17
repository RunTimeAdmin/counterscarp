# Attack Graph Visualization

## Table of Contents

- [Overview](#overview)
- [Generating Attack Graphs](#generating-attack-graphs)
  - [CLI](#cli)
  - [Web Interface](#web-interface)
  - [API](#api)
- [Reading the Visualization](#reading-the-visualization)
  - [Node Types](#node-types)
  - [Edge Types](#edge-types)
  - [Severity Indicators](#severity-indicators)
- [Interactive Features](#interactive-features)
- [Configuration](#configuration)
- [Attack Path Tracing](#attack-path-tracing)
- [Example Attack Paths](#example-attack-paths)
- [Solana Support](#solana-support)
- [Programmatic Access](#programmatic-access)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

---

## Overview

Attack graphs are interactive visual maps showing how vulnerabilities in your smart contracts can be chained together to form exploitable attack paths. Instead of viewing findings in isolation, attack graphs reveal the structural relationships between contracts, functions, and vulnerabilities — showing how an attacker could combine a reentrancy bug with an unchecked external call to drain funds.

The engine parses your Solidity (`.sol`) or Rust/Anchor (`.rs`) source files, extracts contract structure, and links vulnerability findings to the functions and contracts that contain them. The result is a D3.js force-directed graph rendered as a self-contained HTML file.

| Attribute | Value |
|---|---|
| **Tier requirement** | Professional or above |
| **Output format** | Self-contained HTML (D3.js) or JSON |
| **Supported languages** | Solidity, Rust (Anchor/Solana) |
| **Max path depth** | Configurable (default: 10) |

---

## Generating Attack Graphs

### CLI

Attack graphs are generated when `[visualization].enabled = true` in your config and findings are detected during a scan:

```bash
counterscarp --target ./contracts --report
```

Enable visualization in `scarpshield.toml` first (legacy `counterscarp.toml` also works):

```toml
[visualization]
enabled = true
output_format = "html"
```

The graph is saved alongside the report as `attack_graph.html` in the output directory.

To generate both HTML and raw JSON simultaneously:

```toml
[visualization]
enabled = true
output_format = "both"
```

### Web Interface

1. Navigate to the Counterscarp web app and upload your contract files
2. Run a scan — the attack graph is generated automatically if findings are detected
3. On the results page, click the **Attack Graph** button or the **View Attack Graph** link in the visualization section
4. The interactive D3.js graph opens in a new tab

The graph is skipped if no findings are detected. If you have a free-tier account, the Attack Graph button will indicate that a Pro license is required.

### API

```
GET /results/{audit_id}/attack-graph
```

Returns the attack graph as an HTML page with the embedded D3.js visualization.

**Response:** `200 OK` — HTML page with the full interactive graph

**Errors:**

| Status | Condition |
|--------|-----------|
| 404 | Attack graph not generated (no findings detected, Pro license not active, or generation failed) |

---

## Reading the Visualization

### Node Types

The graph contains five node types, each representing a different structural element:

| Node Type | Shape | Description |
|-----------|-------|-------------|
| **Contract** | Rectangle | A smart contract or Anchor program |
| **Function** | Rounded rectangle | A function within a contract |
| **Vulnerability** | Circle | A detected finding, colored by severity |
| **ExternalCall** | Diamond | An external call site (`call`, `delegatecall`, `staticcall`, `transfer`, `send`) — or CPI in Solana |
| **StateVariable** | Hexagon | A storage variable involved in a read/write pattern |

### Edge Types

Edges represent the relationships between nodes:

| Edge Type | Style | Meaning |
|-----------|-------|---------|
| `contains` | Solid gray | A contract contains a function |
| `calls` | Solid arrow | A function makes an external call |
| `delegates` | Dashed arrow | A function uses `delegatecall` |
| `inherits` | Dotted arrow | A contract inherits from another |
| `reads` | Thin blue arrow | Data read from a state variable |
| `writes` | Thin orange arrow | Data written to a state variable |
| `triggers` | Thick red arrow | A function contains this vulnerability |

**Attack paths** are traced along `calls` and `delegates` edges, terminating at `Vulnerability` nodes. These paths are highlighted in red.

### Severity Indicators

Vulnerability nodes are color-coded by severity:

| Severity | Color | Node Size |
|----------|-------|-----------|
| CRITICAL | Red (`#ef4444`) | 20px |
| HIGH | Orange (`#f97316`) | 15px |
| MEDIUM | Yellow (`#eab308`) | 10px |
| LOW | Blue (`#3b82f6`) | 8px |
| INFO | Gray (`#6b7280`) | 5px |

Node size scales with severity — CRITICAL findings appear as larger circles, making them immediately visible in complex graphs.

---

## Interactive Features

The D3.js force-directed visualization supports the following interactions:

- **Zoom** — scroll wheel to zoom in/out on the graph canvas
- **Pan** — click and drag the background to reposition the view
- **Node details** — click any node to reveal a details panel showing: node type, name, severity (for vulnerabilities), file path, line number, and rule ID
- **Hover tooltips** — hover over any node for a quick name/type summary
- **Drag nodes** — click and drag individual nodes to reposition them in the layout
- **Attack path highlighting** — click a `triggers` edge to highlight the full attack path that terminates at that vulnerability

---

## Configuration

Configure attack graph generation in the `[visualization]` section of `scarpshield.toml` (legacy `counterscarp.toml` also works):

```toml
[visualization]
enabled = true                   # Generate attack graphs (default: false)
include_source_analysis = true   # Parse contract source for structure (default: true)
trace_attack_paths = true        # Trace paths through external calls (default: true)
output_format = "html"           # "html", "json", or "both" (default: "html")
max_path_depth = 10              # Max depth for path tracing; 0 = unlimited (default: 10)
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Generate attack graph visualizations |
| `include_source_analysis` | bool | `true` | Parse contract source files to extract contracts, functions, and call sites |
| `trace_attack_paths` | bool | `true` | Trace attack paths through external call chains |
| `output_format` | string | `"html"` | Output format: `html`, `json`, or `both` |
| `max_path_depth` | int | `10` | Maximum depth for DFS path tracing (`0` = unlimited) |

**Note:** `include_source_analysis = false` will produce a graph containing only Vulnerability nodes (no contract/function structure). This is faster but produces less informative graphs.

---

## Attack Path Tracing

When `trace_attack_paths = true`, the engine performs a depth-first search (DFS) starting from every Contract node and every `public`/`external` Function node. The traversal follows `calls` and `delegates` edges and records a path whenever it reaches a Vulnerability node.

Each path represents a potential attack sequence: an entry point → one or more function calls → a vulnerability. The summary statistics include:

- **Total paths found** — number of distinct attack paths traced
- **Vulnerability count** — total vulnerability nodes in the graph
- **Critical / High count** — high-severity nodes specifically
- **Longest path length** — deepest attack chain found
- **Average path length** — mean depth across all paths

Paths are truncated at `max_path_depth` hops to prevent infinite cycles in recursive contracts. Set `max_path_depth = 0` for unlimited traversal (not recommended for contracts with recursive patterns).

---

## Example Attack Paths

### Reentrancy → Fund Drain

```
Vault (Contract)
  └─ withdraw() [public] (Function)
       ├─ [triggers] REENTRANCY (Vulnerability, CRITICAL, line 42)
       └─ [calls] recipient.call() (ExternalCall)
            └─ [triggers] UNCHECKED_EXTERNAL_CALL (Vulnerability, HIGH, line 45)
```

**Interpretation:** An attacker calls `withdraw()`, the external call to `recipient` is made before state is updated, and there is no reentrancy guard — allowing re-entry and balance drain.

### Oracle Manipulation → Price Theft

```
Pool (Contract)
  └─ swap() [external] (Function)
       ├─ [triggers] ORACLE_STALENESS_CHECK (Vulnerability, HIGH)
       └─ [triggers] MISSING_SLIPPAGE_PROTECTION (Vulnerability, HIGH)
```

**Interpretation:** A single stale oracle source with no slippage check enables a flash-loan-funded price manipulation attack.

### Proxy Upgrade → Full Takeover

```
TransparentProxy (Contract)
  └─ upgradeTo() [external] (Function)
       ├─ [triggers] UPGRADE_FUNCTION (Vulnerability, CRITICAL)
       └─ [triggers] STORAGE_COLLISION_RISK (Vulnerability, HIGH)
  └─ [inherits] ProxyAdmin (Contract)
```

**Interpretation:** An inadequately access-controlled upgrade function combined with a storage layout collision allows an attacker to replace the implementation with a malicious contract.

---

## Solana Support

Attack graphs support Rust/Anchor programs (`.rs` files) in addition to Solidity. The mapping is:

| Solidity Concept | Solana/Anchor Equivalent |
|-----------------|--------------------------|
| Contract | Anchor `#[program]` module |
| Function | `pub fn` instruction handler |
| ExternalCall | `invoke()` / `invoke_signed()` CPI call |
| StateVariable | `Account<T>` struct field |

CPI (Cross-Program Invocation) calls are detected and linked to the functions that issue them, enabling attack path tracing across program boundaries.

---

## Programmatic Access

The attack graph engine is importable as a Python library:

```python
from attack_graph import build_graph, export_graph_json, trace_attack_paths, get_attack_path_summary

findings = [
    {
        "rule_id": "REENTRANCY",
        "severity": "CRITICAL",
        "file": "contracts/Vault.sol",
        "line_no": 42,
        "message": "Reentrancy vulnerability in withdraw function"
    }
]

# Build the graph from findings + optional source files
graph = build_graph(findings, source_files=["contracts/Vault.sol"])

# Export D3.js-compatible JSON
json_data = export_graph_json(graph)

# Trace attack paths
paths = trace_attack_paths(graph)
for path in paths:
    print(" -> ".join(path))

# Get summary statistics
summary = get_attack_path_summary(graph)
print(f"Total paths: {summary['total_paths']}")
print(f"Critical vulnerabilities: {summary['critical_vulnerabilities']}")
```

The `export_graph_json` function returns a dictionary with `nodes`, `links`, and `metadata` keys, compatible with D3.js force-directed layouts.

---

## Limitations

- **Cross-file accuracy:** Analysis works best when all related contract files are provided together. Missing imports reduce the completeness of inheritance and call-site edges.
- **Static analysis only:** Attack graphs are built from static parsing — runtime behavior, dynamic dispatch, and proxy storage patterns may not be fully captured.
- **Large codebases:** Projects with many contracts produce dense graphs. Increase `max_path_depth` cautiously — very deep traversal in recursive patterns can be slow.
- **Solidity parsing:** Contract structure is extracted via regex patterns. Highly unusual syntax or inline assembly may not be parsed correctly.
- **Library contracts:** Standard library contracts (OpenZeppelin, solmate, etc.) appear as inherited Contract nodes but are not scanned for vulnerabilities, reducing visual noise.
- **Rust/Anchor:** CPI target program IDs are not resolved statically, so CPI edges show the call type but not the target program name.

---

## Troubleshooting

**Graph is empty (no nodes):**
- Verify the scan produced findings — no findings means no vulnerability nodes, and the graph is skipped
- Check that `[visualization].enabled = true` in `scarpshield.toml` (or legacy `counterscarp.toml`)
- Ensure you have an active Pro license (attack graphs require Pro tier or above)

**Graph shows only vulnerability nodes, no contracts or functions:**
- Set `include_source_analysis = true` and pass the source file paths to the scan
- Confirm that the `.sol` or `.rs` files were uploaded before running the scan

**Graph generation failed silently:**
- Check the scan log for `Failed to build attack graph` errors
- Verify source files are valid Solidity/Rust and readable by the engine

**Attack paths not appearing:**
- Ensure `trace_attack_paths = true`
- Public/external functions are required as entry points — internal-only contracts will not have traced paths
- Increase `max_path_depth` if paths are being cut short in deeply nested call chains

**Web UI shows "Pro license required" on the Attack Graph button:**
- Activate a Pro license via `SCARPSHIELD_PRO_LICENSE` (legacy `COUNTERSCARP_PRO_LICENSE`) or `[license].key` in `scarpshield.toml`
- See the [Getting Started Guide](GETTING_STARTED.md#pro-license-activation) for license setup instructions

---

*Counterscarp Security Engine &bull; counterscarp.io*
