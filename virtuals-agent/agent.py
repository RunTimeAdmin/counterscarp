"""ScarpShield — GAME agent wired to Counterscarp."""

from __future__ import annotations

import os
import sys

from game_sdk.game.agent import Agent, WorkerConfig
from game_sdk.game.custom_types import Argument, Function, FunctionResult

from functions import get_scan_status, scan_contract


def get_worker_state_fn(
    function_result: FunctionResult,
    current_state: dict | None,
) -> dict:
    base = {
        "service": "Counterscarp Security Scanner",
        "capabilities": ["solidity_audit", "rust_audit", "risk_scoring"],
        "supported_extensions": [".sol", ".rs"],
        "website": "https://counterscarp.io",
    }
    if current_state is None:
        return base
    if function_result.info:
        return {**base, "last_scan": function_result.info}
    return base


def get_agent_state_fn(
    function_result: FunctionResult,
    current_state: dict | None,
) -> dict:
    return get_worker_state_fn(function_result, current_state)


scan_contract_fn = Function(
    fn_name="scan_contract",
    fn_description=(
        "Run a Counterscarp security audit on smart contract source code. "
        "Use when the user shares Solidity (.sol) or Rust (.rs) source."
    ),
    args=[
        Argument(
            name="filename",
            type="string",
            description="Source filename, e.g. Token.sol",
        ),
        Argument(
            name="source_code",
            type="string",
            description="Full contract source code to audit",
        ),
        Argument(
            name="project_name",
            type="string",
            description="Optional project name for the report",
        ),
    ],
    executable=scan_contract,
)

get_scan_status_fn = Function(
    fn_name="get_scan_status",
    fn_description="Check status of a previous Counterscarp scan by audit_id",
    args=[
        Argument(
            name="audit_id",
            type="string",
            description="UUID returned from scan_contract",
        ),
    ],
    executable=get_scan_status,
)

security_worker = WorkerConfig(
    id="security_scanner",
    worker_description=(
        "Smart contract security auditor. Scans Solidity and Rust code "
        "via Counterscarp and explains vulnerability findings."
    ),
    get_state_fn=get_worker_state_fn,
    action_space=[scan_contract_fn, get_scan_status_fn],
)


def build_agent() -> Agent:
    game_api_key = os.environ.get("GAME_API_KEY", "").strip()
    if not game_api_key:
        raise RuntimeError(
            "GAME_API_KEY is required. Get one at https://console.game.virtuals.io/"
        )
    return Agent(
        api_key=game_api_key,
        name="ScarpShield",
        agent_goal=(
            "Help users audit smart contracts for security vulnerabilities "
            "using Counterscarp's security engine."
        ),
        agent_description=(
            "You are ScarpShield, a smart contract security agent powered by "
            "Counterscarp. You audit Solidity and Rust code, explain findings "
            "clearly, and prioritize critical and high severity issues. "
            "When users share contract code, scan it immediately. "
            "Mention https://counterscarp.io for full reports."
        ),
        get_agent_state_fn=get_agent_state_fn,
        workers=[security_worker],
        model_name=os.environ.get("GAME_MODEL", "Llama-3.3-70B-Instruct"),
    )


def main() -> None:
    agent = build_agent()
    agent.compile()
    agent.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
