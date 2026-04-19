# Sentinel Engine Architecture

A comprehensive visual documentation of the Sentinel Security Engine's architecture, data flows, and component relationships.

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Analysis Pipeline Flow](#2-analysis-pipeline-flow)
3. [Module Dependency Graph](#3-module-dependency-graph)
4. [Exception Hierarchy](#4-exception-hierarchy)
5. [Configuration System](#5-configuration-system)
6. [Execution Profiles Comparison](#6-execution-profiles-comparison)
7. [Data Flow: Finding Lifecycle](#7-data-flow-finding-lifecycle)
8. [Innovative Features Architecture](#8-innovative-features-architecture)

---

## 1. System Architecture Overview

The Sentinel Engine follows a modular, pipeline-based architecture with a central orchestrator coordinating multiple specialized security analyzers. The system is designed to be extensible, allowing optional analyzers to be integrated based on project requirements.

```mermaid
flowchart TD
    subgraph Interfaces["User Interfaces"]
        CLI["CLI (orchestrator.py)"]
        GUI["GUI (gui.py)"]
    end

    subgraph Orchestrator["Central Orchestrator"]
        ORCH["Orchestrator<br/>Pipeline Controller"]
    end

    subgraph SecurityAnalyzers["Security Analyzers"]
        direction TB
        STATIC["Static Analysis"]
        DYNAMIC["Dynamic Analysis"]
        HEURISTIC["Heuristic Scanner<br/>(31 EVM Rules)"]
        SOLANA["Solana Analyzer<br/>(35 Patterns)"]
        UPGRADE["Upgrade Diff"]
    end

    subgraph StaticTools["Static Analysis Tools"]
        SLITHER["Slither<br/>(red_team_scan)"]
        ADERYN["Aderyn"]
        MYTHRIL["Mythril<br/>(symbolic)"]
    end

    subgraph DynamicTools["Dynamic Analysis Tools"]
        FOUNDRY["Foundry Fuzz"]
        MEDUSA["Medusa"]
    end

    subgraph ThreatIntel["Threat Intelligence"]
        KNOWLEDGE["Knowledge Fetcher"]
        SOLANA_INTEL["Solana Intel"]
        C4["Code4rena"]
        IMMUNEFI["Immunefi"]
        SOLODIT["Solodit"]
        NEODYME["Neodyme"]
        OTTERSEC["OtterSec"]
        SEC3["Sec3"]
    end

    subgraph SupplyChain["Supply Chain"]
        SCC["supply_chain_check"]
        OSV["OSV.dev API"]
    end

    subgraph Innovative["Innovative Features"]
        direction TB
        RAG["RAG Engine<br/>(rag_engine.py)"]
        EMB["Embeddings<br/>(embeddings.py)"]
        AG["Attack Graph<br/>(attack_graph.py)"]
        VIS["Visualizer<br/>(visualizer.py)"]
        HIST["History Scanner<br/>(history_scanner.py)"]
        IDL["IDL Validator<br/>(idl_validator.py)"]
        PIPE["Pipeline Gen<br/>(pipeline_generator.py)"]
        FP["Fingerprint<br/>(fingerprint_scanner.py)"]
        PDB["Protocol DB<br/>(protocol_db.py)"]
    end

    subgraph Infrastructure["Core Infrastructure"]
        LOGGER["logger.py"]
        EXCEPTIONS["exceptions.py"]
        CONFIG["config_loader.py"]
        HTTP["http_utils.py"]
    end

    subgraph Reporting["Report Generation"]
        REPORT["report_generator.py"]
        HTML["HTML Reports"]
        MD["Markdown Reports"]
        SARIF["SARIF Reports"]
    end

    subgraph ExternalTools["External Tools"]
        EXT_SLITHER["slither"]
        EXT_ADERYN["aderyn"]
        EXT_MEDUSA["medusa"]
        EXT_MYTH["myth"]
        EXT_FORGE["forge"]
        EXT_OPENAI["OpenAI API"]
        EXT_ANTHROPIC["Anthropic API"]
    end

    CLI --> ORCH
    GUI --> ORCH
    ORCH --> SecurityAnalyzers
    ORCH --> SupplyChain
    ORCH --> ThreatIntel
    ORCH --> Innovative
    ORCH --> Reporting

    STATIC --> SLITHER
    STATIC --> ADERYN
    STATIC --> MYTHRIL

    DYNAMIC --> FOUNDRY
    DYNAMIC --> MEDUSA

    KNOWLEDGE --> C4
    KNOWLEDGE --> IMMUNEFI
    KNOWLEDGE --> SOLODIT

    SOLANA_INTEL --> NEODYME
    SOLANA_INTEL --> OTTERSEC
    SOLANA_INTEL --> SEC3

    SCC --> OSV

    RAG --> EMB
    RAG --> EXT_OPENAI
    RAG --> EXT_ANTHROPIC
    AG --> VIS
    FP --> PDB

    SLITHER --> EXT_SLITHER
    ADERYN --> EXT_ADERYN
    MEDUSA --> EXT_MEDUSA
    MYTHRIL --> EXT_MYTH
    FOUNDRY --> EXT_FORGE

    SecurityAnalyzers -.-> LOGGER
    SecurityAnalyzers -.-> EXCEPTIONS
    SecurityAnalyzers -.-> CONFIG
    ThreatIntel -.-> HTTP
    SupplyChain -.-> HTTP
    Innovative -.-> HTTP
    Innovative -.-> LOGGER
    Innovative -.-> CONFIG
    HTTP -.-> LOGGER
    HTTP -.-> CONFIG

    REPORT --> HTML
    REPORT --> MD
    REPORT --> SARIF

    style ORCH fill:#e1f5fe
    style LOGGER fill:#fff3e0
    style EXCEPTIONS fill:#fff3e0
    style CONFIG fill:#fff3e0
    style REPORT fill:#e8f5e9
    style Innovative fill:#f3e5f5
```

---

## 2. Analysis Pipeline Flow

The orchestrator executes a 13-phase sequential pipeline. Each phase can be enabled/disabled via configuration or command-line flags. Optional phases are marked with decision nodes.

```mermaid
flowchart TD
    START(["Start Analysis"]) --> DEC0

    DEC0{"RAG enabled?"} -->|Yes| PHASE0
    DEC0 -->|No| PHASE1

    PHASE0["Phase 0: RAG Knowledge Enrichment<br/>AI Copilot context loading"] --> PHASE1

    PHASE1["Phase 1: Supply Chain Analysis<br/>OSV.dev vulnerability check"] --> PHASE2
    PHASE1 -.->|"No package.json"| PHASE2

    PHASE2["Phase 2: Static Analysis - Slither<br/>Core vulnerability detection"] --> DEC2

    DEC2{"Aderyn enabled?"} -->|Yes| PHASE2B
    DEC2 -->|No| DEC3

    PHASE2B["Phase 2B: Static Analysis - Aderyn<br/>Rust-based Solidity analyzer"] --> DEC3

    DEC3{"Foundry fuzz contract?"} -->|Yes| PHASE3
    DEC3 -->|No| DEC4

    PHASE3["Phase 3: Fuzzing - Foundry<br/>Invariant testing"] --> DEC4

    DEC4{"Medusa enabled?"} -->|Yes| PHASE3B
    DEC4 -->|No| DEC4A

    PHASE3B["Phase 3B: Fuzzing - Medusa<br/>Coverage-guided fuzzing"] --> DEC4A

    DEC4A{"Fingerprint scan enabled?"} -->|Yes| PHASE3C
    DEC4A -->|No| PHASE4

    PHASE3C["Phase 3C: Protocol Fingerprinting<br/>Similarity analysis"] --> PHASE4

    PHASE4["Phase 4: Heuristic Scan<br/>31 EVM security rules"] --> DEC5

    DEC5{"Symbolic analysis enabled?"} -->|Yes| PHASE5
    DEC5 -->|No| DEC5A

    PHASE5["Phase 5: Symbolic Execution - Mythril<br/>Path exploration"] --> DEC5A

    DEC5A{"History scan enabled?"} -->|Yes| PHASE5B
    DEC5A -->|No| DEC6

    PHASE5B["Phase 5B: Time-Travel Scan<br/>Git history analysis"] --> DEC6

    DEC6{"Solana root provided?"} -->|Yes| PHASE6
    DEC6 -->|No| DEC6A

    PHASE6["Phase 6: Solana Analysis<br/>35 Anchor/Rust patterns"] --> DEC6A

    DEC6A{"IDL validation enabled?"} -->|Yes| PHASE6B
    DEC6A -->|No| DEC7

    PHASE6B["Phase 6B: Anchor IDL Validation<br/>Constraint & CPI analysis"] --> DEC7

    DEC7{"Upgrade paths provided?"} -->|Yes| PHASE7
    DEC7 -->|No| DEC7A

    PHASE7["Phase 7: Upgrade Diff Analysis<br/>Implementation comparison"] --> DEC7A

    DEC7A{"Attack graph enabled?"} -->|Yes| PHASE7B
    DEC7A -->|No| PHASE8

    PHASE7B["Phase 7B: Attack Path Visualization<br/>Cross-contract graph"] --> PHASE8

    PHASE8["Phase 8: Report Generation<br/>Markdown action plan"] --> DEC9

    DEC9{"Professional report requested?"} -->|Yes| PHASE9
    DEC9 -->|No| END1

    PHASE9["Phase 9: Professional Reports<br/>HTML / Markdown / SARIF"] --> END2

    END1(["Action Plan Generated"])
    END2(["Full Audit Reports Generated"])

    style PHASE0 fill:#f3e5f5
    style PHASE1 fill:#ffebee
    style PHASE2 fill:#ffebee
    style PHASE2B fill:#fff3e0
    style PHASE3 fill:#fff3e0
    style PHASE3B fill:#fff3e0
    style PHASE3C fill:#f3e5f5
    style PHASE4 fill:#ffebee
    style PHASE5 fill:#fff3e0
    style PHASE5B fill:#f3e5f5
    style PHASE6 fill:#fff3e0
    style PHASE6B fill:#f3e5f5
    style PHASE7 fill:#fff3e0
    style PHASE7B fill:#f3e5f5
    style PHASE8 fill:#e8f5e9
    style PHASE9 fill:#e8f5e9
    style DEC0 fill:#e3f2fd
    style DEC2 fill:#e3f2fd
    style DEC3 fill:#e3f2fd
    style DEC4 fill:#e3f2fd
    style DEC4A fill:#e3f2fd
    style DEC5 fill:#e3f2fd
    style DEC5A fill:#e3f2fd
    style DEC6 fill:#e3f2fd
    style DEC6A fill:#e3f2fd
    style DEC7 fill:#e3f2fd
    style DEC7A fill:#e3f2fd
    style DEC9 fill:#e3f2fd
```

---

## 3. Module Dependency Graph

This diagram shows the import dependencies between modules. Core infrastructure modules are at the base, with analyzers and interfaces building on top.

```mermaid
flowchart LR
    subgraph CoreInfra["Core Infrastructure"]
        direction TB
        EXC["exceptions.py"]
        LOG["logger.py"]
        CFG["config_loader.py"]
        HTTP["http_utils.py"]
    end

    subgraph Analyzers["Security Analyzers"]
        direction TB
        RTS["red_team_scan.py"]
        HS["heuristic_scanner.py"]
        FW["fuzz_wrapper.py"]
        SW["symbolic_wrapper.py"]
        AW["aderyn_wrapper.py"]
        MW["medusa_wrapper.py"]
        SA["solana_analyzer.py"]
        UD["upgrade_diff.py"]
        IC["intent_check.py"]
        AM["access_matrix.py"]
    end

    subgraph APIModules["API Modules"]
        direction TB
        KF["knowledge_fetcher.py"]
        SI["solana_intel.py"]
        SCC["supply_chain_check.py"]
        TI["threat_intel.py"]
    end

    subgraph Innovative["Innovative Features"]
        direction TB
        RAG["rag_engine.py"]
        EMB["embeddings.py"]
        AG["attack_graph.py"]
        VIS["visualizer.py"]
        HIST["history_scanner.py"]
        IDL["idl_validator.py"]
        PIPE["pipeline_generator.py"]
        FP["fingerprint_scanner.py"]
        PDB["protocol_db.py"]
    end

    subgraph Interfaces["Interfaces"]
        direction TB
        ORCH["orchestrator.py"]
        GUI["gui.py"]
    end

    subgraph Reporting["Reporting"]
        RG["report_generator.py"]
    end

    subgraph Exploit["Exploit Generation"]
        EG["exploit_generator.py"]
    end

    subgraph Inflation["Inflation"]
        IS["inflation_scaffold.py"]
    end

    %% Core dependencies
    CFG -.-> LOG
    CFG -.-> EXC
    HTTP -.-> LOG
    HTTP -.-> EXC
    HTTP -.-> CFG

    %% Analyzers depend on core
    RTS -.-> LOG
    RTS -.-> EXC
    HS -.-> LOG
    HS -.-> EXC
    HS -.-> CFG
    FW -.-> LOG
    FW -.-> EXC
    SW -.-> LOG
    SW -.-> EXC
    AW -.-> LOG
    AW -.-> EXC
    MW -.-> LOG
    MW -.-> EXC
    SA -.-> LOG
    SA -.-> EXC
    UD -.-> LOG
    UD -.-> EXC
    IC -.-> LOG
    IC -.-> EXC
    AM -.-> LOG
    AM -.-> EXC

    %% API modules depend on http_utils
    KF -.-> HTTP
    SI -.-> HTTP
    SCC -.-> HTTP
    TI -.-> HTTP

    %% Innovative features dependencies
    RAG -.-> EMB
    RAG -.-> HTTP
    RAG -.-> LOG
    AG -.-> VIS
    AG -.-> LOG
    HIST -.-> LOG
    HIST -.-> CFG
    IDL -.-> LOG
    IDL -.-> SA
    PIPE -.-> LOG
    PIPE -.-> CFG
    FP -.-> PDB
    FP -.-> HTTP
    FP -.-> LOG
    PDB -.-> LOG

    %% Reporting depends on core
    RG -.-> LOG
    RG -.-> EXC

    %% Orchestrator imports everything
    ORCH --> RTS
    ORCH --> SCC
    ORCH --> FW
    ORCH --> HS
    ORCH --> SW
    ORCH --> AW
    ORCH --> MW
    ORCH --> SA
    ORCH --> UD
    ORCH --> CFG
    ORCH --> RG
    ORCH --> RAG
    ORCH --> AG
    ORCH --> HIST
    ORCH --> IDL
    ORCH --> PIPE
    ORCH --> FP

    %% GUI imports most modules
    GUI -.-> ORCH
    GUI -.-> HS
    GUI -.-> RTS
    GUI -.-> SCC

    style CoreInfra fill:#fff3e0
    style Analyzers fill:#ffebee
    style APIModules fill:#e3f2fd
    style Innovative fill:#f3e5f5
    style Interfaces fill:#e8f5e9
    style Reporting fill:#f3e5f5
    style Exploit fill:#fce4ec
    style Inflation fill:#fce4ec
```

---

## 4. Exception Hierarchy

Sentinel Engine uses a custom exception hierarchy for structured error handling. All exceptions inherit from `SentinelError` and support optional details dictionaries for structured context.

```mermaid
classDiagram
    class SentinelError {
        +str message
        +dict details
        +__init__(message, details)
        +__str__() str
        +to_dict() dict
    }

    class SentinelConfigError {
        +Configuration loading/validation errors
    }

    class SentinelAnalysisError {
        +Security analyzer failures
    }

    class SentinelAPIError {
        +External API call failures
    }

    class SentinelReportError {
        +Report generation failures
    }

    class SentinelToolNotFoundError {
        +Required external tool not found
    }

    class SentinelValidationError {
        +Input validation failures
    }

    class SentinelTimeoutError {
        +Operation timeout errors
    }

    SentinelError <|-- SentinelConfigError
    SentinelError <|-- SentinelAnalysisError
    SentinelError <|-- SentinelAPIError
    SentinelError <|-- SentinelReportError
    SentinelError <|-- SentinelToolNotFoundError
    SentinelError <|-- SentinelValidationError
    SentinelError <|-- SentinelTimeoutError
```

### Exception Usage Examples

| Exception | Usage Context | Example Details |
|-----------|---------------|-----------------|
| `SentinelConfigError` | Invalid TOML syntax, missing required keys | `{"path": "config.toml", "line": 42}` |
| `SentinelAnalysisError` | Slither/Aderyn/Mythril execution failure | `{"tool": "slither", "contract": "Token.sol"}` |
| `SentinelAPIError` | OSV.dev, threat intel API failures | `{"api": "osv", "status_code": 503}` |
| `SentinelReportError` | HTML/MD/SARIF generation failure | `{"format": "html", "output_path": "/reports"}` |
| `SentinelToolNotFoundError` | Missing external tool in PATH | `{"tool": "mythril", "install_cmd": "pip install mythril"}` |
| `SentinelValidationError` | Invalid input parameters | `{"field": "address", "value": "0x123"}` |
| `SentinelTimeoutError` | Analysis exceeding time limits | `{"operation": "symbolic_analysis", "timeout_seconds": 300}` |

---

## 5. Configuration System

The configuration system uses a layered approach with base configuration and profile-specific overrides. All configuration is validated and loaded into typed dataclasses.

```mermaid
flowchart LR
    subgraph ConfigFiles["Configuration Files"]
        BASE["sentinel.toml<br/>Base Configuration"]
        PR["sentinel-pr.toml<br/>PR Mode Profile"]
        AUDIT["sentinel-audit.toml<br/>Audit Mode Profile"]
        BOUNTY["sentinel-bounty.toml<br/>Bounty Mode Profile"]
    end

    subgraph Loader["Config Loader"]
        LOADER["config_loader.py"]
        VALIDATE["Validation Engine"]
    end

    subgraph DataClasses["Typed Dataclasses"]
        ROOT["SentinelConfig<br/>Root Configuration"]

        subgraph Sections["21 Configuration Sections"]
            ENGINE["EngineConfig"]
            HEUR["HeuristicConfig"]
            SUPP["Suppression list"]
            STATIC["StaticAnalysisConfig"]
            FUZZ["FuzzingConfig"]
            RED["RedTeamConfig"]
            EXT["ExternalToolsConfig"]
            SC["SupplyChainConfig"]
            TI["ThreatIntelConfig"]
            HTTP["HttpConfig"]
            CHAIN["ChainConfig"]
            UPGRADE["UpgradeDiffConfig"]
            REP["ReportingConfig"]
            CI["CIConfig"]
            AI["AIConfig"]
            VIZ["VisualizationConfig"]
            HIST["HistoryConfig"]
            IDL["IDLConfig"]
            CIGEN["CIGeneratorConfig"]
            EXP["ExploitGenerationConfig"]
            FP["FingerprintConfig"]
        end
    end

    subgraph Consumers["Module Consumers"]
        MODULES["Individual Analysis Modules"]
    end

    BASE --> LOADER
    PR -->|"Override"| LOADER
    AUDIT -->|"Override"| LOADER
    BOUNTY -->|"Override"| LOADER

    LOADER --> VALIDATE
    VALIDATE --> ROOT

    ROOT --> ENGINE
    ROOT --> HEUR
    ROOT --> SUPP
    ROOT --> STATIC
    ROOT --> FUZZ
    ROOT --> RED
    ROOT --> EXT
    ROOT --> SC
    ROOT --> TI
    ROOT --> HTTP
    ROOT --> CHAIN
    ROOT --> UPGRADE
    ROOT --> REP
    ROOT --> CI

    ROOT --> MODULES

    style ConfigFiles fill:#e3f2fd
    style Loader fill:#fff3e0
    style DataClasses fill:#e8f5e9
    style Sections fill:#f1f8e9
    style Consumers fill:#ffebee
```

### Configuration Sections Overview

| Section | Dataclass | Purpose |
|---------|-----------|---------|
| `engine` | `EngineConfig` | Engine name, version, fail severity, max findings |
| `heuristics` | `HeuristicConfig` | Heuristic scanner enable/disable, rule overrides |
| `suppressions` | `List[Suppression]` | Finding suppression rules with file/line/expiration |
| `static_analysis` | `StaticAnalysisConfig` | Slither/Aderyn settings, detector filters |
| `fuzzing` | `FuzzingConfig` | Foundry/Medusa settings, runs, timeouts |
| `red_team` | `RedTeamConfig` | Severity allowlist, ignored checks |
| `external_tools` | `ExternalToolsConfig` | Tool-specific timeouts |
| `supply_chain` | `SupplyChainConfig` | OSV.dev settings, ecosystem, rate limits |
| `threat_intel` | `ThreatIntelConfig` | API timeouts for C4, Immunefi, Solana sources |
| `http` | `HttpConfig` | HTTP client retry, backoff, timeout settings |
| `chains` | `ChainConfig` | Solana/EVM chain-specific settings |
| `upgrade_diff` | `UpgradeDiffConfig` | Upgrade comparison settings |
| `reporting` | `ReportingConfig` | Output format, sections, verbosity |
| `ci` | `CIConfig` | CI/CD integration settings |
| `ai` | `AIConfig` | RAG, LLM provider, embedding settings |
| `visualization` | `VisualizationConfig` | Attack graph, output format settings |
| `history` | `HistoryConfig` | Git history scan, blame attribution |
| `chains.solana.idl` | `IDLConfig` | Anchor IDL validation settings |
| `ci.generator` | `CIGeneratorConfig` | Pipeline generation settings |
| `exploit_generation` | `ExploitGenerationConfig` | Exploit template, LLM settings |
| `fingerprint` | `FingerprintConfig` | Protocol similarity, database settings |

---

## 6. Execution Profiles Comparison

Sentinel Engine provides three pre-configured execution profiles optimized for different use cases.

| Feature | PR Mode | Audit Mode | Bounty Mode |
|---------|---------|------------|-------------|
| **Config file** | `sentinel-pr.toml` | `sentinel-audit.toml` | `sentinel-bounty.toml` |
| **Target time** | < 2 min | 10-30 min | 1-2 hours |
| **Slither** | Yes | Yes | Yes |
| **Aderyn** | No | Yes | Yes |
| **Foundry fuzz** | No | Yes (250K runs) | Yes (500K runs) |
| **Medusa** | No | No | Yes |
| **Mythril** | No | No | Optional |
| **Heuristics** | 31 rules | 31 rules | 31 rules |
| **Threat Intel** | Yes | Yes | Yes |
| **AI PoC Gen** | No | No | Yes |
| **Fail threshold** | HIGH+ | MEDIUM+ | None (report all) |
| **Report formats** | Markdown | HTML + MD | HTML + MD + SARIF |

### Profile Selection Guide

- **PR Mode**: Fast feedback for continuous integration. Focuses on critical issues only.
- **Audit Mode**: Balanced depth for standard security audits. Includes all major analyzers.
- **Bounty Mode**: Maximum coverage for bug bounty preparation. Enables all optional tools.

---

## 7. Data Flow: Finding Lifecycle

This sequence diagram shows how a security finding flows through the system from detection to final report output.

```mermaid
sequenceDiagram
    participant Analyzer as Security Analyzer
    participant Orchestrator as Orchestrator
    participant Config as Config Loader
    participant ReportGen as Report Generator
    participant Output as Output Files

    Analyzer->>Analyzer: Detect vulnerability<br/>in source code
    Analyzer->>Analyzer: Classify severity<br/>(CRITICAL/HIGH/MEDIUM/LOW)
    Analyzer->>Orchestrator: Return raw finding<br/>(rule_id, file, line, message)

    Orchestrator->>Config: Check suppression<br/>is_finding_suppressed()

    alt Finding is suppressed
        Config-->>Orchestrator: Return Suppression object
        Orchestrator->>Orchestrator: Mark as suppressed<br/>Skip from report
    else Finding not suppressed
        Config-->>Orchestrator: Return None
        Orchestrator->>Orchestrator: Add to active findings list
    end

    Orchestrator->>Orchestrator: Aggregate findings<br/>from all analyzers

    Orchestrator->>ReportGen: Pass findings collection<br/>(severity-sorted)

    ReportGen->>ReportGen: Format findings<br/>by report type

    alt Markdown Report
        ReportGen->>ReportGen: Generate action plan<br/>with remediation steps
        ReportGen->>Output: Write ACTION_PLAN_*.md
    end

    alt HTML Report
        ReportGen->>ReportGen: Generate styled HTML<br/>with syntax highlighting
        ReportGen->>Output: Write audit_report_*.html
    end

    alt SARIF Report
        ReportGen->>ReportGen: Format as SARIF 2.1.0<br/>for GitHub integration
        ReportGen->>Output: Write *.sarif
    end

    Output-->>Orchestrator: Confirm file paths
    Orchestrator->>Orchestrator: Display summary<br/>to user
```

### Finding Data Structure

```python
@dataclass
class Finding:
    rule_id: str           # Unique identifier (e.g., "reentrancy-eth")
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str          # Heuristic, Slither, Aderyn, etc.
    title: str             # Human-readable title
    description: str       # Detailed description
    file: str             # Source file path
    line_no: int          # Line number
    code_snippet: str     # Affected code
    remediation: str       # Fix suggestion (optional)
```

### Suppression Matching Logic

1. **Rule ID Match**: Finding's rule_id must match suppression rule_id
2. **File Match** (optional): If suppression specifies file, exact or path match required
3. **Line Match** (optional): If suppression specifies line, exact line number required
4. **Expiration Check**: If suppression has expires date, must not be past due

---

## 8. Innovative Features Architecture

This section details how the 7 innovative features integrate with the core Sentinel Engine architecture.

### 8.1 AI Audit Copilot (RAG System)

The RAG-based knowledge system enriches findings with contextual explanations from historical audit data.

```mermaid
flowchart LR
    subgraph Input["Finding Input"]
        FINDING["Security Finding<br/>rule_id, code_snippet"]
    end

    subgraph RAGPipeline["RAG Pipeline"]
        EMB["Embedding Generator<br/>(embeddings.py)"]
        VDB["Vector Database<br/>Local/Remote"]
        RETRIEVE["Context Retrieval<br/>top_k similar findings"]
        PROMPT["Prompt Builder<br/>System + Context + Finding"]
    end

    subgraph LLM["LLM Providers"]
        OPENAI["OpenAI API<br/>GPT-4"]
        ANTHROPIC["Anthropic API<br/>Claude"]
    end

    subgraph Output["Enriched Output"]
        EXPLANATION["Vulnerability Explanation"]
        FIX["Suggested Fix"]
        REFS["References & CWE"]
    end

    FINDING --> EMB
    EMB --> VDB
    VDB --> RETRIEVE
    RETRIEVE --> PROMPT
    PROMPT --> OPENAI
    PROMPT --> ANTHROPIC
    OPENAI --> EXPLANATION
    ANTHROPIC --> EXPLANATION
    EXPLANATION --> FIX
    EXPLANATION --> REFS
```

**Key Components:**
- `rag_engine.py` - Main RAG orchestrator
- `embeddings.py` - Text embedding generation (local + API)
- Vector store for historical audit embeddings
- Prompt templates for vulnerability explanation

---

### 8.2 Attack Path Visualizer

Generates interactive force-directed graphs showing cross-contract vulnerability chains.

```mermaid
flowchart TD
    subgraph DataCollection["Data Collection"]
        FINDINGS["Security Findings"]
        CALLGRAPH["Call Graph<br/>Cross-contract calls"]
        STATE["State Dependencies<br/>Storage variables"]
    end

    subgraph GraphBuilder["Attack Graph Builder<br/>(attack_graph.py)"]
        NODES["Node Extraction<br/>Contracts, Functions"]
        EDGES["Edge Creation<br/>Calls, Dependencies"]
        RISK["Risk Scoring<br/>Severity propagation"]
    end

    subgraph Visualization["Visualization<br/>(visualizer.py)"]
        D3["D3.js Force Graph"]
        INTERACTIVE["Interactive Controls<br/>Zoom, Filter, Highlight"]
        EXPORT["Export Formats<br/>HTML, Mermaid, DOT"]
    end

    FINDINGS --> NODES
    CALLGRAPH --> EDGES
    STATE --> EDGES
    NODES --> RISK
    EDGES --> RISK
    RISK --> D3
    D3 --> INTERACTIVE
    INTERACTIVE --> EXPORT
```

---

### 8.3 Time-Travel Scanner

Git-based historical analysis for tracking when vulnerabilities were introduced.

```mermaid
flowchart LR
    subgraph Git["Git Repository"]
        LOG["Git Log<br/>Commit history"]
        DIFF["Git Diff<br/>File changes"]
        BLAME["Git Blame<br/>Line attribution"]
    end

    subgraph Scanner["History Scanner<br/>(history_scanner.py)"]
        COMMITS["Commit Iterator<br/>--commits N"]
        CHECKOUT["Checkout & Scan<br/>Incremental analysis"]
        TRACK["Vulnerability Tracker<br/>Introduction/Fix dates"]
    end

    subgraph Output["Output"]
        TIMELINE["Security Timeline"]
        DEBT["Technical Debt Report"]
        ATTRIB["Contributor Attribution"]
    end

    LOG --> COMMITS
    DIFF --> CHECKOUT
    BLAME --> TRACK
    COMMITS --> CHECKOUT
    CHECKOUT --> TRACK
    TRACK --> TIMELINE
    TRACK --> DEBT
    TRACK --> ATTRIB
```

---

### 8.4 Anchor IDL Validator

Solana-specific IDL validation for Anchor programs.

```mermaid
flowchart TD
    subgraph Input["Anchor Project"]
        IDL["IDL JSON<br/>Interface Definition"]
        RS["Rust Source<br/>Program code"]
    end

    subgraph Validation["IDL Validator<br/>(idl_validator.py)"]
        PARSE["IDL Parser<br/>Accounts, Instructions"]
        CONSTRAINT["Constraint Checker<br/>signer, mut, has_one"]
        CPI["CPI Flow Tracer<br/>Cross-program calls"]
        MATRIX["Permission Matrix<br/>Account access rights"]
    end

    subgraph Output["Validation Output"]
        ERRORS["Constraint Violations"]
        FLOWS["CPI Flow Diagrams"]
        PERMS["Account Permission Map"]
    end

    IDL --> PARSE
    RS --> CONSTRAINT
    PARSE --> CONSTRAINT
    CONSTRAINT --> CPI
    CPI --> MATRIX
    CONSTRAINT --> ERRORS
    CPI --> FLOWS
    MATRIX --> PERMS
```

---

### 8.5 CI/CD Pipeline Generator

Multi-platform pipeline generation for security automation.

```mermaid
flowchart LR
    subgraph Config["Configuration"]
        TOML["sentinel.toml<br/>User config"]
        PROFILES["Execution Profiles<br/>PR/Audit/Bounty"]
    end

    subgraph Generator["Pipeline Generator<br/>(pipeline_generator.py)"]
        TEMPLATES["Template Engine<br/>Jinja2"]
        GITHUB["GitHub Actions<br/>.github/workflows/"]
        GITLAB["GitLab CI<br/>.gitlab-ci.yml"]
        AZURE["Azure DevOps<br/>azure-pipelines.yml"]
        JENKINS["Jenkins<br/>Jenkinsfile"]
    end

    subgraph Features["Pipeline Features"]
        PR["PR Comments<br/>Findings summary"]
        SARIF["SARIF Upload<br/>GitHub Security"]
        NOTIFY["Notifications<br/>Slack/Discord"]
    end

    TOML --> TEMPLATES
    PROFILES --> TEMPLATES
    TEMPLATES --> GITHUB
    TEMPLATES --> GITLAB
    TEMPLATES --> AZURE
    TEMPLATES --> JENKINS
    GITHUB --> PR
    GITHUB --> SARIF
    GITLAB --> NOTIFY
```

---

### 8.6 Enhanced Exploit Generator

Pattern-to-template exploit generation with multi-LLM support.

```mermaid
flowchart TD
    subgraph Input["Vulnerability Input"]
        RULE["Rule ID<br/>REENTRANCY, etc."]
        CODE["Vulnerable Code<br/>Snippet"]
        CONTEXT["Contract Context<br/>State variables"]
    end

    subgraph Generator["Exploit Generator<br/>(exploit_generator.py)]
        MAPPER["Pattern Mapper<br/>Rule → Template"]
        TEMPLATES["Template Library<br/>6 Foundry templates"]
        INFERENCE["State Inference<br/>Setup generation"]
        ORACLE["Assertion Oracle<br/>Exploit validation"]
    end

    subgraph LLM["LLM Integration"]
        OPENAI["OpenAI<br/>GPT-4"]
        ANTHROPIC["Anthropic<br/>Claude"]
    end

    subgraph Output["Generated Exploit"]
        TEST["Foundry Test<br/>*.t.sol"]
        SETUP["Deployment Script"]
        PROOF["Proof of Concept"]
    end

    RULE --> MAPPER
    CODE --> INFERENCE
    CONTEXT --> INFERENCE
    MAPPER --> TEMPLATES
    TEMPLATES --> OPENAI
    TEMPLATES --> ANTHROPIC
    INFERENCE --> OPENAI
    INFERENCE --> ANTHROPIC
    ORACLE --> OPENAI
    OPENAI --> TEST
    ANTHROPIC --> TEST
    TEST --> SETUP
    TEST --> PROOF
```

---

### 8.7 Protocol Fingerprint Scanner

Protocol similarity detection and inherited vulnerability analysis.

```mermaid
flowchart LR
    subgraph Database["Protocol Database<br/>(protocol_db.py)"]
        UNI["Uniswap V2/V3"]
        COMP["Compound"]
        AAVE["Aave"]
        OZ["OpenZeppelin"]
        CUSTOM["Custom Fingerprints"]
    end

    subgraph Scanner["Fingerprint Scanner<br/>(fingerprint_scanner.py)"]
        AST["AST Analysis<br/>Structure extraction"]
        SIMILARITY["Similarity Engine<br/>Cosine/Jaccard"]
        MATCHING["Protocol Matching<br/>Threshold > 0.75"]
    end

    subgraph Analysis["Vulnerability Analysis"]
        INHERIT["Inherited Vulns<br/>From parent protocol"]
        HISTORY["Exploit History<br/>Known issues"]
        RISK["Risk Scoring<br/>Genetic risk"]
    end

    subgraph Output["Fingerprint Report"]
        MATCH["Protocol Match<br/>% similarity"]
        WARNINGS["Inherited Warnings"]
        RECS["Recommendations"]
    end

    UNI --> AST
    COMP --> AST
    AAVE --> AST
    OZ --> AST
    CUSTOM --> AST
    AST --> SIMILARITY
    SIMILARITY --> MATCHING
    MATCHING --> INHERIT
    MATCHING --> HISTORY
    INHERIT --> RISK
    HISTORY --> RISK
    MATCHING --> MATCH
    RISK --> WARNINGS
    RISK --> RECS
```

---

## Appendix: Module Reference

| Module | Purpose | Key Classes/Functions |
|--------|---------|----------------------|
| `orchestrator.py` | CLI entry point, pipeline controller | `main()`, `generate_markdown_report()` |
| `red_team_scan.py` | Slither integration | `run_slither()`, `filter_vulnerabilities()` |
| `heuristic_scanner.py` | Pattern-based analysis | `scan_target()`, `HeuristicFinding` |
| `fuzz_wrapper.py` | Foundry fuzzing | `run_foundry_fuzz()`, `parse_counterexamples()` |
| `symbolic_wrapper.py` | Mythril integration | `run_mythril()`, `parse_issues()` |
| `aderyn_wrapper.py` | Aderyn integration | `run_aderyn()` |
| `medusa_wrapper.py` | Medusa fuzzing | `run_medusa_fuzz()` |
| `solana_analyzer.py` | Solana/Anchor analysis | `analyze_solana_program()` |
| `upgrade_diff.py` | Upgrade safety | `analyze_upgrade()` |
| `supply_chain_check.py` | Dependency scanning | `scan_package_json()` |
| `knowledge_fetcher.py` | Threat intelligence | Fetch from C4, Immunefi, Solodit |
| `solana_intel.py` | Solana-specific intel | Fetch from Neodyme, OtterSec, Sec3 |
| `report_generator.py` | Professional reports | `create_audit_report()`, `Finding` |
| `config_loader.py` | Configuration management | `load_config()`, `SentinelConfig` |
| `logger.py` | Structured logging | `get_logger()` |
| `exceptions.py` | Custom exceptions | `SentinelError` hierarchy |
| `http_utils.py` | Resilient HTTP client | Retry, backoff, rate limiting |
| `gui.py` | Tkinter GUI interface | GUI application |
| `intent_check.py` | Liar Detector | NatSpec validation |
| `access_matrix.py` | Access control analysis | Permission mapping |
| `exploit_generator.py` | AI PoC generation | Exploit templates |
| `inflation_scaffold.py` | Tokenomics analysis | Inflation detection |
| `threat_intel.py` | Core threat intel | Intelligence aggregation |
| `rag_engine.py` | RAG knowledge retrieval | `query_knowledge_base()`, `enrich_finding()` |
| `embeddings.py` | Text embeddings | `generate_embedding()`, `EmbeddingCache` |
| `attack_graph.py` | Attack path construction | `build_attack_graph()`, `find_attack_paths()` |
| `visualizer.py` | Interactive visualization | `generate_d3_graph()`, `export_mermaid()` |
| `history_scanner.py` | Git history analysis | `scan_history()`, `blame_vulnerability()` |
| `idl_validator.py` | Anchor IDL validation | `validate_idl()`, `trace_cpi_flows()` |
| `pipeline_generator.py` | CI/CD pipeline gen | `generate_github_actions()`, `generate_gitlab_ci()` |
| `fingerprint_scanner.py` | Protocol similarity | `fingerprint_contract()`, `find_inherited_vulns()` |
| `protocol_db.py` | Protocol fingerprint DB | `ProtocolFingerprint`, `SimilarityEngine` |
