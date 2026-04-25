"""Fuzzing phases: FoundryFuzzPhase, MedusaFuzzPhase."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from scan_phase import ScanContext, ScanPhase


class FoundryFuzzPhase(ScanPhase):
    """Phase 3 — Foundry invariant fuzzing (optional, --fuzz-contract flag)."""

    def __init__(self) -> None:
        super().__init__(name="foundry_fuzz", display_name="Foundry Fuzz")

    def should_run(self, ctx: ScanContext) -> bool:
        return bool(getattr(ctx.args, "fuzz_contract", None))

    def run(self, ctx: ScanContext) -> List[Dict]:
        import fuzz_wrapper
        from exceptions import CounterscarpAnalysisError, CounterscarpToolNotFoundError

        fuzz_issues: List[Dict] = []
        _fuzz_error: Optional[str] = None
        try:
            raw_logs = fuzz_wrapper.run_foundry_fuzz(
                ctx.args.fuzz_contract,
                stderr_log=ctx.stderr_log,
            )
            fuzz_issues = fuzz_wrapper.parse_counterexamples(raw_logs)
            ctx.logger.info(
                "Foundry fuzz complete: %d counterexamples found", len(fuzz_issues)
            )
        except CounterscarpToolNotFoundError as e:
            ctx.logger.warning("Foundry not found — skipping fuzz: %s", e)
            _fuzz_error = str(e)
        except CounterscarpAnalysisError as e:
            ctx.logger.error("Foundry fuzz failed: %s", e)
            _fuzz_error = str(e)
        except Exception as e:
            ctx.logger.error("Foundry fuzz unexpected failure: %s", e)
            _fuzz_error = str(e)

        ctx.fuzz_issues = fuzz_issues
        ctx.analyzer_status["Foundry Fuzz"] = {
            "ran": bool(fuzz_issues) or _fuzz_error is None,
            "finding_count": len(fuzz_issues),
            "error": _fuzz_error,
        }
        return fuzz_issues

    async def run_async(self, ctx: ScanContext) -> List[Dict]:
        """Async version — runs Foundry via async subprocess."""
        import asyncio
        import sys
        from pathlib import Path

        fuzz_issues: List[Dict] = []
        _fuzz_error: Optional[str] = None

        fuzz_contract = getattr(ctx.args, "fuzz_contract", None)
        if not fuzz_contract:
            return fuzz_issues

        try:
            import async_subprocess
            import fuzz_wrapper
            from exceptions import CounterscarpAnalysisError

            fuzz_runs = fuzz_wrapper.get_fuzz_runs()
            cmd = [
                "forge",
                "test",
                "--match-contract", fuzz_contract,
                "--fuzz-runs", str(fuzz_runs),
                "-vvv",
            ]
            result = await async_subprocess.run_tool(cmd, timeout=3600)
            if result.stderr and ctx.stderr_log:
                try:
                    from logger import append_stderr_log
                    append_stderr_log(result.stderr, "forge-fuzz", ctx.stderr_log)
                except Exception:
                    pass
            fuzz_issues = fuzz_wrapper.parse_counterexamples(result.stdout)
            ctx.logger.info(
                "Foundry fuzz complete (async): %d counterexamples", len(fuzz_issues)
            )
        except Exception as e:
            ctx.logger.error("Foundry fuzz async failed — falling back to sync: %s", e)
            # Fall back to sync via executor
            loop = asyncio.get_running_loop()
            try:
                fuzz_issues = await loop.run_in_executor(None, self.run, ctx)
                return fuzz_issues
            except Exception as fe:
                _fuzz_error = str(fe)
                fuzz_issues = []

        ctx.fuzz_issues = fuzz_issues
        ctx.analyzer_status["Foundry Fuzz"] = {
            "ran": bool(fuzz_issues) or _fuzz_error is None,
            "finding_count": len(fuzz_issues),
            "error": _fuzz_error,
        }
        return fuzz_issues


class MedusaFuzzPhase(ScanPhase):
    """Phase 3B — Medusa coverage-guided fuzzing (optional, --medusa flag + directory)."""

    def __init__(self) -> None:
        super().__init__(name="medusa_fuzz", display_name="Medusa (Fuzzing)")

    def should_run(self, ctx: ScanContext) -> bool:
        return bool(getattr(ctx.args, "medusa", False)) and os.path.isdir(ctx.target)

    def run(self, ctx: ScanContext) -> Any:
        import types as _types

        medusa_wrapper_mod: Optional[_types.ModuleType] = None
        try:
            import medusa_wrapper as _mw
            medusa_wrapper_mod = _mw
        except ImportError:
            pass

        medusa_results: Optional[Dict] = None
        _medusa_error: Optional[str] = None

        if medusa_wrapper_mod is None:
            ctx.logger.warning("medusa_wrapper module not available")
            _medusa_error = "medusa_wrapper module not available"
        else:
            try:
                fuzz_contract = getattr(ctx.args, "fuzz_contract", None)
                medusa_results = medusa_wrapper_mod.run_medusa_fuzz(
                    ctx.target,
                    target_contract=fuzz_contract or None,
                    stderr_log=ctx.stderr_log,
                )
                ctx.logger.info("Medusa fuzzing complete")
            except Exception as e:
                ctx.logger.error("Medusa fuzzing failed: %s", e)
                medusa_results = {"error": "Medusa fuzzing failed"}
                _medusa_error = str(e)

        ctx.medusa_results = medusa_results
        _medusa_count = (
            len((medusa_results or {}).get("findings", []))
            if isinstance(medusa_results, dict) and not (medusa_results or {}).get("error")
            else 0
        )
        ctx.analyzer_status["Medusa (Fuzzing)"] = {
            "ran": medusa_results is not None
            and not (isinstance(medusa_results, dict) and medusa_results.get("error")),
            "finding_count": _medusa_count,
            "error": _medusa_error,
        }
        return medusa_results

    async def run_async(self, ctx: ScanContext) -> Any:
        """Async version — runs Medusa via async subprocess."""
        import asyncio
        import types as _types

        medusa_results: Optional[Dict] = None
        _medusa_error: Optional[str] = None

        try:
            import async_subprocess
            import medusa_wrapper as _mw

            fuzz_contract = getattr(ctx.args, "fuzz_contract", None)
            test_limit = _mw.get_medusa_test_limit()
            timeout_sec = _mw.get_medusa_timeout()

            cmd = [
                "medusa",
                "fuzz",
                "--target", ctx.target,
                "--test-limit", str(test_limit),
                "--timeout", str(timeout_sec),
                "--coverage-enabled",
                "--json-output",
            ]
            if fuzz_contract:
                cmd.extend(["--contract-name", fuzz_contract])

            result = await async_subprocess.run_tool(cmd, timeout=timeout_sec + 60)
            if result.stderr and ctx.stderr_log:
                try:
                    from logger import append_stderr_log
                    append_stderr_log(result.stderr, "medusa-fuzz", ctx.stderr_log)
                except Exception:
                    pass

            # Parse JSON output produced by --json-output flag
            medusa_results = _mw.parse_medusa_output(result.stdout, result.stderr)
            ctx.logger.info("Medusa fuzzing complete (async)")
        except ImportError:
            # medusa_wrapper not available — skip silently
            _medusa_error = "medusa_wrapper module not available"
        except Exception as e:
            ctx.logger.error("Medusa async failed — falling back to sync: %s", e)
            loop = asyncio.get_running_loop()
            try:
                medusa_results = await loop.run_in_executor(None, self.run, ctx)
                return medusa_results
            except Exception as fe:
                _medusa_error = str(fe)

        ctx.medusa_results = medusa_results
        _medusa_count = (
            len((medusa_results or {}).get("findings", []))
            if isinstance(medusa_results, dict) and not (medusa_results or {}).get("error")
            else 0
        )
        ctx.analyzer_status["Medusa (Fuzzing)"] = {
            "ran": medusa_results is not None
            and not (isinstance(medusa_results, dict) and medusa_results.get("error")),
            "finding_count": _medusa_count,
            "error": _medusa_error,
        }
        return medusa_results
