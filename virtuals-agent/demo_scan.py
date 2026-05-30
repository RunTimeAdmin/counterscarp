"""Smoke test: Counterscarp API wiring without a GAME API key."""

from __future__ import annotations

import json
import sys

from counterscarp_client import CounterscarpClient

DEMO_CONTRACT = """
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
""".strip()


def main() -> int:
    client = CounterscarpClient()
    print(f"Submitting demo scan to {client.base_url} ...")
    result = client.scan_contract(
        filename="Vulnerable.sol",
        content=DEMO_CONTRACT,
        project_name="Docker Demo",
    )
    print(json.dumps(
        {
            "audit_id": result.get("audit_id"),
            "status": result.get("status"),
            "summary": result.get("summary"),
            "report_urls": result.get("report_urls"),
            "finding_count": len(result.get("findings") or []),
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Demo scan failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
