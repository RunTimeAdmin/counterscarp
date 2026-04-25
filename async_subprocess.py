"""Async subprocess wrapper for external tool execution."""

from __future__ import annotations

import asyncio
import subprocess
import logging

logger = logging.getLogger(__name__)


async def run_tool(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Run an external tool asynchronously with timeout.

    Args:
        cmd: Command and arguments list.
        timeout: Maximum execution time in seconds.
        cwd: Working directory for the subprocess.
        env: Environment variables for the subprocess.

    Returns:
        CompletedProcess with stdout/stderr as strings.

    Raises:
        CounterscarpAnalysisError: If the tool times out.
    """
    from exceptions import CounterscarpAnalysisError

    logger.debug("Running async: %s (timeout=%ds)", cmd[0], timeout)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise CounterscarpAnalysisError(
            f"Tool timed out after {timeout}s: {cmd[0]}"
        )

    return subprocess.CompletedProcess(
        cmd,
        proc.returncode if proc.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace") if stdout else "",
        stderr.decode("utf-8", errors="replace") if stderr else "",
    )
