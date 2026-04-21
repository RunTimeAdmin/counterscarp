from __future__ import annotations

import os
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from typing import Any

from logger import get_logger
from exceptions import (
    CounterscarpError,
    CounterscarpConfigError,
    CounterscarpAnalysisError,
    CounterscarpToolNotFoundError,
    CounterscarpValidationError,
)

logger = get_logger(__name__)

import red_team_scan
import supply_chain_check
import fuzz_wrapper
import access_matrix
import symbolic_wrapper
import heuristic_scanner
import knowledge_fetcher
import intent_check
import aderyn_wrapper
import medusa_wrapper
import solana_analyzer
import upgrade_diff

# Optional config loader
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
    logger.debug("Config loader available")
except ImportError as e:
    logger.warning(f"Config loader not available: {e}")
    CONFIG_AVAILABLE = False
    CounterscarpConfig = None


def append_output(widget: scrolledtext.ScrolledText, text: str) -> None:
    """Append text to the scrolled text widget.

    Args:
        widget: The scrolled text widget to append to.
        text: The text to append.
    """
    widget.insert(tk.END, text + "\n")
    widget.see(tk.END)


def create_gui() -> None:
    """Create and run the Counterscarp Security Engine GUI.

    Initializes the main application window with controls for running
    various security checks on smart contracts.
    """
    root = tk.Tk()
    root.title("Pragmatic Security Engine - GUI")

    # Top-level exception handler to prevent silent crashes
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            root.destroy()
            return
        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        messagebox.showerror("Critical Error", f"An unexpected error occurred:\n\n{error_msg[:500]}...")

    import sys
    sys.excepthook = handle_exception

    # Paths
    tk.Label(root, text="Solidity contract (.sol):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
    contract_entry = tk.Entry(root, width=60)
    contract_entry.grid(row=0, column=1, padx=5, pady=5)

    def browse_contract() -> None:
        """Open file dialog to select a Solidity contract file."""
        path = filedialog.askopenfilename(
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")]
        )
        if path:
            contract_entry.delete(0, tk.END)
            contract_entry.insert(0, path)

    tk.Button(root, text="Browse", command=browse_contract).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(root, text="Project root (for supply chain / fuzz):").grid(
        row=1, column=0, sticky="w", padx=5, pady=5
    )
    project_entry = tk.Entry(root, width=60)
    project_entry.grid(row=1, column=1, padx=5, pady=5)

    def browse_project() -> None:
        """Open directory dialog to select project root."""
        path = filedialog.askdirectory()
        if path:
            project_entry.delete(0, tk.END)
            project_entry.insert(0, path)

    tk.Button(root, text="Browse", command=browse_project).grid(row=1, column=2, padx=5, pady=5)

    # Fuzz config
    tk.Label(root, text="Fuzz invariant contract name (Foundry):").grid(
        row=2, column=0, sticky="w", padx=5, pady=5
    )
    fuzz_contract_entry = tk.Entry(root, width=40)
    fuzz_contract_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

    # Checkboxes
    static_var = tk.IntVar(value=1)
    supply_var = tk.IntVar(value=1)
    fuzz_var = tk.IntVar(value=0)
    access_var = tk.IntVar(value=1)
    symbolic_var = tk.IntVar(value=0)
    heuristic_var = tk.IntVar(value=1)
    caselaw_var = tk.IntVar(value=0)  # Code4rena case law
    liar_var = tk.IntVar(value=1)  # Liar Detector
    aderyn_var = tk.IntVar(value=0)  # Aderyn static analyzer
    medusa_var = tk.IntVar(value=0)  # Medusa fuzzing
    solana_var = tk.IntVar(value=0)  # Solana/Anchor static analysis
    upgrade_var = tk.IntVar(value=0)  # Upgrade diff analyzer

    tk.Checkbutton(root, text="Static (Slither)", variable=static_var).grid(
        row=3, column=0, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Supply chain (OSV)", variable=supply_var).grid(
        row=3, column=1, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Fuzz (Foundry)", variable=fuzz_var).grid(
        row=3, column=2, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Aderyn Static", variable=aderyn_var).grid(
        row=3, column=3, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Access matrix", variable=access_var).grid(
        row=4, column=0, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Symbolic (Mythril)", variable=symbolic_var).grid(
        row=4, column=1, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Heuristic scan", variable=heuristic_var).grid(
        row=4, column=2, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Medusa Fuzzing", variable=medusa_var).grid(
        row=4, column=3, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="🤥 Liar Detector (Intent Check)", variable=liar_var).grid(
        row=5, column=0, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="🧠 Threat Intel (C4/Immunefi/Solodit)", variable=caselaw_var).grid(
        row=5, column=1, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Solana Static (Rust/Anchor)", variable=solana_var).grid(
        row=5, column=2, sticky="w", padx=5
    )
    tk.Checkbutton(root, text="Upgrade Diff Analyzer", variable=upgrade_var).grid(
        row=5, column=3, sticky="w", padx=5
    )

    # Old contract path for upgrade diff
    tk.Label(root, text="Old contract (.sol) for upgrade diff (optional):").grid(
        row=6, column=0, sticky="w", padx=5, pady=5
    )
    old_contract_entry = tk.Entry(root, width=60)
    old_contract_entry.grid(row=6, column=1, padx=5, pady=5)

    def browse_old_contract() -> None:
        """Open file dialog to select old contract for upgrade diff."""
        path = filedialog.askopenfilename(
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")]
        )
        if path:
            old_contract_entry.delete(0, tk.END)
            old_contract_entry.insert(0, path)

    tk.Button(root, text="Browse", command=browse_old_contract).grid(row=6, column=2, padx=5, pady=5)

    # Output area
    output = scrolledtext.ScrolledText(root, width=100, height=30)
    output.grid(row=7, column=0, columnspan=3, padx=5, pady=5)

    def run_checks() -> None:
        """Run all selected security checks and display results."""
        try:
            output.delete("1.0", tk.END)
            contract_path = contract_entry.get().strip()
            project_root = project_entry.get().strip()
            fuzz_contract_name = fuzz_contract_entry.get().strip()
            old_contract_path = old_contract_entry.get().strip()

            if not any(
                [
                    static_var.get(),
                    supply_var.get(),
                    fuzz_var.get(),
                    access_var.get(),
                    symbolic_var.get(),
                    heuristic_var.get(),
                    caselaw_var.get(),
                    liar_var.get(),
                    aderyn_var.get(),
                    medusa_var.get(),
                    solana_var.get(),
                    upgrade_var.get(),
                ]
            ):
                messagebox.showinfo("Info", "Please select at least one check to run.")
                return

            if (static_var.get() or access_var.get() or symbolic_var.get() or heuristic_var.get() or liar_var.get()) and not contract_path:
                messagebox.showerror("Error", "Please choose a Solidity contract file.")
                return

            # If project root not specified, try to infer from contract path
            if not project_root and contract_path:
                project_root = os.path.dirname(contract_path)

            # 1. Supply chain
            if supply_var.get():
                append_output(output, "=== Supply Chain (OSV.dev) ===")
                if not project_root:
                    append_output(output, "[!] No project root provided; skipping supply chain check.")
                else:
                    pkg_path = os.path.join(project_root, "package.json")
                    if not os.path.exists(pkg_path):
                        append_output(output, f"[!] package.json not found at {pkg_path}; skipping.")
                    else:
                        try:
                            vulns = supply_chain_check.scan_package_json(pkg_path)
                            if not vulns:
                                append_output(output, "[+] No known vulnerabilities found.")
                            else:
                                for v in vulns:
                                    append_output(
                                        output,
                                        f"[VULNERABLE] {v['library']} v{v['installed']} - {v.get('summary', '')}",
                                    )
                        except FileNotFoundError as e:
                            logger.error(f"Package.json not found: {e}")
                            append_output(output, f"[!] package.json not found: {e}")
                        except PermissionError as e:
                            logger.error(f"Permission denied reading package.json: {e}")
                            append_output(output, f"[!] Permission denied: {e}")
                        except Exception as e:
                            logger.error(f"Error running supply chain check: {e}")
                            append_output(output, "[!] Error running supply chain check:")
                            append_output(output, traceback.format_exc())

            # 2. Static analysis (Slither)
            if static_var.get():
                append_output(output, "\n=== Static Analysis (Slither) ===")
                try:
                    # Prevent sys.exit() from killing the GUI
                    import sys
                    old_exit = sys.exit
                    sys.exit = lambda code=0: None

                    raw = red_team_scan.run_slither(contract_path)
                    findings = red_team_scan.filter_vulnerabilities(raw)
                    if not findings:
                        append_output(output, "[+] No High/Medium issues found.")
                    else:
                        for f in findings:
                            append_output(
                                output,
                                f"[{f['impact']}] {f['title']} @ {f['location']}",
                            )
                except FileNotFoundError as e:
                    logger.error(f"Slither not found: {e}")
                    append_output(output, "[!] Slither not found. Install: pip install slither-analyzer")
                except PermissionError as e:
                    logger.error(f"Permission denied running Slither: {e}")
                    append_output(output, f"[!] Permission denied running Slither: {e}")
                except Exception as e:
                    logger.error(f"Error running Slither: {e}")
                    append_output(output, "[!] Error running Slither:")
                    append_output(output, traceback.format_exc())
                finally:
                    sys.exit = old_exit

            # 2b. Aderyn Static Analysis
            if aderyn_var.get():
                append_output(output, "\n=== Aderyn Static Analysis ===")
                if not project_root:
                    append_output(output, "[!] No project root provided; skipping Aderyn.")
                else:
                    try:
                        import sys as _sys
                        old_exit = _sys.exit
                        _sys.exit = lambda code=0: None

                        results = aderyn_wrapper.run_aderyn(project_root)
                    except FileNotFoundError as e:
                        logger.error(f"Aderyn not found: {e}")
                        append_output(output, "[!] Aderyn not found. Install: cargo install aderyn")
                        results = None
                    except PermissionError as e:
                        logger.error(f"Permission denied running Aderyn: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                        results = None
                    except Exception as e:
                        logger.error(f"Error running Aderyn: {e}")
                        append_output(output, "[!] Error running Aderyn:")
                        append_output(output, traceback.format_exc())
                        results = None
                    finally:
                        try:
                            _sys.exit = old_exit
                        except (NameError, AttributeError) as e:
                            logger.debug(f"Could not restore sys.exit: {e}")

                    if isinstance(results, dict) and not results.get("error"):
                        total = results.get("total", 0)
                        high_count = len(results.get("high", []))
                        low_count = len(results.get("low", []))
                        nc_count = len(results.get("nc", []))
                        append_output(
                            output,
                            f"[*] Total issues: {total} (High: {high_count}, Low: {low_count}, Non-critical: {nc_count})",
                        )
                        high_issues = results.get("high", [])[:5]
                        for issue in high_issues:
                            title = issue.get("title", "Unknown issue")
                            detector = issue.get("detector_name", "unknown")
                            append_output(
                                output,
                                f"[HIGH] {title} (Detector: {detector})",
                            )
                    elif isinstance(results, dict) and results.get("error"):
                        append_output(output, f"[!] Aderyn error: {results['error']}")

            # 3. Access matrix
            if access_var.get():
                append_output(output, "\n=== Access Control Matrix ===")
                try:
                    funcs = access_matrix.parse_solidity_file(contract_path)
                    for f in funcs:
                        if f["visibility"] in ["internal", "private"]:
                            continue
                        risk = f["risk"]
                        label = risk
                        if risk == "HIGH":
                            label = "🚨 PUBLIC"
                        elif risk == "ADMIN":
                            label = "🛡️ ADMIN"
                        elif f["mutability"] == "READ":
                            label = "VIEW"
                        auth_str = ", ".join(f["auth"]) if f["auth"] else "Anyone"
                        if f["mods"]:
                            auth_str += f" (+{', '.join(f['mods'])})"
                        append_output(
                            output,
                            f"{label:>10} | {f['name']} ({f['visibility']}, {f['mutability']}) -> {auth_str}",
                        )
                except FileNotFoundError as e:
                    logger.error(f"Contract file not found for access matrix: {e}")
                    append_output(output, f"[!] Contract file not found: {e}")
                except PermissionError as e:
                    logger.error(f"Permission denied reading contract: {e}")
                    append_output(output, f"[!] Permission denied: {e}")
                except Exception as e:
                    logger.error(f"Error generating access matrix: {e}")
                    append_output(output, "[!] Error generating access matrix:")
                    append_output(output, traceback.format_exc())

            # 4. Fuzzing (Foundry)
            if fuzz_var.get():
                append_output(output, "\n=== Fuzzing (Foundry) ===")
                if not project_root:
                    append_output(output, "[!] No project root provided; skipping fuzzing.")
                elif not fuzz_contract_name:
                    append_output(output, "[!] Please specify the invariant test contract name.")
                else:
                    try:
                        # Prevent sys.exit() from killing the GUI
                        import sys
                        old_exit = sys.exit
                        sys.exit = lambda code=0: None
                        
                        cwd = os.getcwd()
                        os.chdir(project_root)
                        raw_logs = fuzz_wrapper.run_foundry_fuzz(fuzz_contract_name)
                        exploits = fuzz_wrapper.parse_counterexamples(raw_logs)
                    except FileNotFoundError as e:
                        logger.error(f"Foundry not found: {e}")
                        append_output(output, "[!] Foundry not found. Install: https://book.getfoundry.sh")
                        exploits = []
                    except PermissionError as e:
                        logger.error(f"Permission denied running fuzzing: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                        exploits = []
                    except Exception as e:
                        logger.error(f"Error running fuzzing: {e}")
                        append_output(output, "[!] Error running fuzzing:")
                        append_output(output, traceback.format_exc())
                        exploits = []
                    finally:
                        sys.exit = old_exit
                        try:
                            os.chdir(cwd)
                        except (OSError, FileNotFoundError) as e:
                            logger.warning(f"Could not restore working directory: {e}")

                    if not exploits:
                        append_output(output, "[+] No invariants broken.")
                    else:
                        for ex in exploits:
                            append_output(output, f"[VULNERABLE] {ex['test_name']} - {ex['reason']}")
                            for step in ex["steps"]:
                                append_output(output, f"    -> {step}")

            # 4b. Medusa Fuzzing
            if medusa_var.get():
                append_output(output, "\n=== Medusa Fuzzing ===")
                if not project_root:
                    append_output(output, "[!] No project root provided; skipping Medusa fuzzing.")
                else:
                    try:
                        import sys as _sys
                        old_exit = _sys.exit
                        _sys.exit = lambda code=0: None

                        medusa_root = project_root
                        results = medusa_wrapper.run_medusa_fuzz(medusa_root, target_contract=fuzz_contract_name or None)
                    except FileNotFoundError as e:
                        logger.error(f"Medusa not found: {e}")
                        append_output(output, "[!] Medusa not found. Install: https://github.com/crytic/medusa")
                        results = None
                    except PermissionError as e:
                        logger.error(f"Permission denied running Medusa: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                        results = None
                    except Exception as e:
                        logger.error(f"Error running Medusa: {e}")
                        append_output(output, "[!] Error running Medusa:")
                        append_output(output, traceback.format_exc())
                        results = None
                    finally:
                        try:
                            _sys.exit = old_exit
                        except (NameError, AttributeError) as e:
                            logger.debug(f"Could not restore sys.exit: {e}")

                    if isinstance(results, dict) and not results.get("error"):
                        findings = results.get("findings", [])
                        stats = results.get("statistics", {})
                        total_seq = results.get("total_sequences", "unknown")
                        cov = stats.get("coverage_percent", "N/A")
                        append_output(output, f"[*] Total sequences: {total_seq}, Coverage: {cov}%")
                        if not findings:
                            append_output(output, "[+] No invariant violations found by Medusa.")
                        else:
                            append_output(output, f"[!] Medusa found {len(findings)} invariant violations:")
                            for fnd in findings[:5]:
                                append_output(output, f"    - {fnd.get('test', 'unknown')} ({fnd.get('status', '')})")
                    elif isinstance(results, dict) and results.get("error"):
                        append_output(output, f"[!] Medusa error: {results['error']}")

            # 5. Symbolic (Mythril)
            if symbolic_var.get():
                append_output(output, "\n=== Symbolic Analysis (Mythril) ===")
                try:
                    # Prevent sys.exit() from killing the GUI
                    import sys
                    old_exit = sys.exit
                    sys.exit = lambda code=0: None
                    
                    raw = symbolic_wrapper.run_mythril(contract_path)
                    issues = symbolic_wrapper.parse_issues(raw)
                    if not issues:
                        append_output(output, "[+] No issues reported by Mythril.")
                    else:
                        for i, issue in enumerate(issues, 1):
                            title = issue.get("title") or "Unnamed issue"
                            severity = issue.get("severity") or "UNKNOWN"
                            line = f"[{i}] {severity} - {title}"
                            if issue.get("swc_id"):
                                line += f" (SWC {issue['swc_id']})"
                            append_output(output, line)
                except FileNotFoundError as e:
                    logger.error(f"Mythril not found: {e}")
                    append_output(output, "[!] Mythril not found. Install: pip install mythril")
                except PermissionError as e:
                    logger.error(f"Permission denied running Mythril: {e}")
                    append_output(output, f"[!] Permission denied: {e}")
                except Exception as e:
                    logger.error(f"Error running Mythril: {e}")
                    append_output(output, "[!] Error running Mythril:")
                    append_output(output, traceback.format_exc())
                finally:
                    sys.exit = old_exit

            # 6. Heuristic scan
            if heuristic_var.get():
                append_output(output, "\n=== Heuristic Scan ===")
                try:
                    # Load config if available
                    config = None
                    if CONFIG_AVAILABLE:
                        try:
                            config = load_config()
                            if config and (config.heuristics.disabled_rules or config.suppressions):
                                append_output(
                                    output,
                                    f"[*] Config loaded: {len(config.heuristics.disabled_rules)} rules disabled, "
                                    f"{len(config.suppressions)} suppressions active",
                                )
                        except (CounterscarpConfigError, IOError) as e:
                            logger.warning(f"Could not load config for heuristic scan: {e}")
                        except Exception as e:
                            logger.warning(f"Unexpected error loading config: {e}")

                    target_for_heuristics = contract_path or project_root
                    if not target_for_heuristics:
                        append_output(output, "[!] No contract or project root; skipping heuristic scan.")
                    else:
                        findings = heuristic_scanner.scan_target(target_for_heuristics, config)
                        active_findings = [f for f in findings if not f.suppressed]
                        suppressed_findings = [f for f in findings if f.suppressed]

                        if not active_findings:
                            append_output(output, "[+] No heuristic flags detected.")
                        else:
                            for fnd in active_findings:
                                append_output(
                                    output,
                                    f"[{fnd.severity}] {fnd.rule_id} - {fnd.message} @ {fnd.file}:{fnd.line_no}",
                                )

                        if suppressed_findings:
                            append_output(output, f"\n🔕 {len(suppressed_findings)} finding(s) suppressed via config")
                except FileNotFoundError as e:
                    logger.error(f"Target not found for heuristic scan: {e}")
                    append_output(output, f"[!] Target not found: {e}")
                except PermissionError as e:
                    logger.error(f"Permission denied for heuristic scan: {e}")
                    append_output(output, f"[!] Permission denied: {e}")
                except Exception as e:
                    logger.error(f"Error running heuristic scan: {e}")
                    append_output(output, "[!] Error running heuristic scan:")
                    append_output(output, traceback.format_exc())

            # 7. Liar Detector (Intent Check)
            if liar_var.get():
                append_output(output, "\n=== 🤥 LIAR DETECTOR (Intent vs. Implementation) ===")
                if not contract_path:
                    append_output(output, "[!] No contract file; skipping liar detector.")
                else:
                    try:
                        issues = intent_check.analyze_intent(contract_path)
                        if not issues:
                            append_output(output, "[+] CLEAN. Code matches developer intent.")
                            append_output(output, "    All restricted functions have proper access controls.")
                        else:
                            append_output(output, f"[⚠️] CRITICAL: Found {len(issues)} intent/implementation mismatches!\n")
                            for issue in issues:
                                append_output(output, f"[{issue['severity']}] Line {issue['line_no']}: {issue['function_name']}")
                                append_output(output, f"  • Claimed:  {issue['claimed_behavior']}")
                                append_output(output, f"  • Actual:   {issue['actual_behavior']}")
                                append_output(output, f"  • Issue:    {issue['description']}")
                                append_output(output, "-" * 60)
                    except FileNotFoundError as e:
                        logger.error(f"Contract file not found for intent check: {e}")
                        append_output(output, f"[!] Contract file not found: {e}")
                    except PermissionError as e:
                        logger.error(f"Permission denied reading contract: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                    except Exception as e:
                        logger.error(f"Error running Liar Detector: {e}")
                        append_output(output, "[!] Error running Liar Detector:")
                        append_output(output, traceback.format_exc())

            # 8. Solana/Anchor Static Analysis
            if solana_var.get():
                append_output(output, "\n=== Solana/Anchor Static Analysis ===")
                if not project_root:
                    append_output(output, "[!] No project root provided; skipping Solana analysis.")
                else:
                    cargo_toml = os.path.join(project_root, "Cargo.toml")
                    if not os.path.exists(cargo_toml):
                        append_output(output, f"[!] Cargo.toml not found at {cargo_toml}; not a Solana/Anchor project.")
                    else:
                        try:
                            results = solana_analyzer.analyze_solana_program(project_root)
                            summary = results.get("summary", {})
                            append_output(
                                output,
                                f"[*] Findings → CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
                                f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}",
                            )
                        except FileNotFoundError as e:
                            logger.error(f"Solana project files not found: {e}")
                            append_output(output, f"[!] Solana project files not found: {e}")
                        except PermissionError as e:
                            logger.error(f"Permission denied reading Solana project: {e}")
                            append_output(output, f"[!] Permission denied: {e}")
                        except Exception as e:
                            logger.error(f"Error running Solana analyzer: {e}")
                            append_output(output, "[!] Error running Solana analyzer:")
                            append_output(output, traceback.format_exc())

            # 9. Upgrade Diff Analyzer
            if upgrade_var.get():
                append_output(output, "\n=== Upgrade Diff Analyzer ===")
                if not old_contract_path or not contract_path:
                    append_output(output, "[!] Both OLD and NEW contract paths are required for upgrade diff.")
                else:
                    try:
                        results = upgrade_diff.analyze_upgrade(old_contract_path, contract_path)
                        summary = results.get("summary", {})
                        append_output(
                            output,
                            f"[*] Storage variables: {results.get('old_storage_count', 0)} → {results.get('new_storage_count', 0)}",
                        )
                        append_output(
                            output,
                            f"[*] Functions: {results.get('old_function_count', 0)} → {results.get('new_function_count', 0)}",
                        )
                        append_output(
                            output,
                            f"[*] Issues → CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
                            f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}",
                        )
                        if results.get("safe"):
                            append_output(output, "✅ SAFE TO UPGRADE (no critical/high issues).")
                        else:
                            append_output(
                                output,
                                "⚠️ UNSAFE TO UPGRADE – address critical/high issues before deploying.",
                            )
                    except FileNotFoundError as e:
                        logger.error(f"Contract file not found for upgrade diff: {e}")
                        append_output(output, f"[!] Contract file not found: {e}")
                    except PermissionError as e:
                        logger.error(f"Permission denied reading contract: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                    except Exception as e:
                        logger.error(f"Error running upgrade diff analyzer: {e}")
                        append_output(output, "[!] Error running upgrade diff analyzer:")
                        append_output(output, traceback.format_exc())

            # 10. Code4rena Case Law
            if caselaw_var.get():
                append_output(output, "\n=== 🧠 THREAT INTELLIGENCE (C4 + Immunefi + Solodit) ===")
                if not contract_path:
                    append_output(output, "[!] No contract file; skipping threat intelligence lookup.")
                else:
                    try:
                        context_tags = knowledge_fetcher.get_contract_context(contract_path)
                        if context_tags:
                            append_output(output, f"[*] Contract Type: {', '.join(context_tags)}")
                        else:
                            append_output(output, "[*] Contract Type: Generic Smart Contract")
                            context_tags = ["Smart Contract"]
                        
                        append_output(output, "[*] Querying threat intelligence databases...\n")
                        
                        # Fetch Code4rena
                        append_output(output, "--- CODE4RENA (High-Severity Audit Findings) ---")
                        c4_findings = knowledge_fetcher.fetch_c4_findings(context_tags[:3])
                        if c4_findings:
                            for i, item in enumerate(c4_findings, 1):
                                append_output(output, f"{i}. {item['title']}")
                                append_output(output, f"   🔗 {item['html_url']}")
                        else:
                            append_output(output, "   [+] No recent high-severity findings")
                        
                        # Fetch Immunefi
                        append_output(output, "\n--- IMMUNEFI (Major Exploit Post-Mortems) ---")
                        immunefi_reports = knowledge_fetcher.fetch_immunefi_reports(context_tags)
                        if immunefi_reports:
                            for i, item in enumerate(immunefi_reports, 1):
                                append_output(output, f"{i}. {item['title']}")
                                append_output(output, f"   🔗 {item['url']}")
                        else:
                            append_output(output, "   [+] No recent exploit reports (Check DeFiHackLabs manually)")
                        
                        # Generate Solodit Deep Links
                        append_output(output, "\n--- SOLODIT (Deep Research Links) ---")
                        solodit_links = knowledge_fetcher.generate_solodit_links(context_tags[:2])
                        for link in solodit_links:
                            append_output(output, f"• {link['title']}")
                            append_output(output, f"   🔗 {link['url']}")
                        
                    except FileNotFoundError as e:
                        logger.error(f"Contract file not found for threat intel: {e}")
                        append_output(output, f"[!] Contract file not found: {e}")
                    except PermissionError as e:
                        logger.error(f"Permission denied reading contract: {e}")
                        append_output(output, f"[!] Permission denied: {e}")
                    except Exception as e:
                        logger.error(f"Error fetching threat intelligence: {e}")
                        append_output(output, "[!] Error fetching threat intelligence:")
                        append_output(output, traceback.format_exc())

            append_output(output, "\n" + "="*60)
            append_output(output, "SCAN COMPLETE")
            append_output(output, "="*60)

        except Exception as e:
            logger.critical(f"Critical error in run_checks: {e}", exc_info=True)
            append_output(output, "\n" + "="*60)
            append_output(output, "CRITICAL ERROR IN run_checks():")
            append_output(output, "="*60)
            append_output(output, traceback.format_exc())
            messagebox.showerror(
                "Scan Error",
                f"A critical error occurred during the scan:\n\n{str(e)}"
            )

    tk.Button(root, text="Run Selected Checks", command=run_checks).grid(
        row=8, column=0, columnspan=3, pady=10
    )

    root.mainloop()


if __name__ == "__main__":
    create_gui()
