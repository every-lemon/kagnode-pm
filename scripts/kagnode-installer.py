#!/usr/bin/python3
"""Typed KagNode CLI installer entry point; no guessed provisioning commands."""

import argparse
import json
from pathlib import Path
import sys
import tomllib

import installer_protocol as protocol
import native_install as native

SOURCE = Path(__file__).resolve().parents[1]


def plan(request):
    if request["mode"] != "native":
        raise ValueError(
            "Proxy Manager requires reviewed native setup; live adoption uses the separate migration procedure"
        )
    state = native.inspect(request.get("configuration", {}), SOURCE)
    value = {
        "schema": 1,
        "project": "proxy-manager",
        "version": tomllib.loads((SOURCE / "Cargo.toml").read_text())["package"][
            "version"
        ],
        "mode": "native",
        "operation_id": request["operation_id"],
        "root": request["root"],
        **state,
    }
    value["plan_sha256"] = protocol.plan_digest(value)
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "apply", "status", "health", "recover"))
    p.add_argument("--request", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    request = protocol.read_request(args.request, "proxy-manager")
    if args.action == "plan":
        result = plan(request)
    elif args.action == "apply":
        protocol.reviewed_plan(request, plan(request))
        result = native.initialize(request.get("configuration", {}), SOURCE)
        result["health"] = native.health()
        if not result["health"]["healthy"]:
            result.update(completed=False, state="needs_recovery")
    elif args.action in ("status", "health"):
        result = native.health()
    else:
        result = {
            "completed": False,
            "state": "needs_recovery",
            "health": native.health(),
            "message": "Inspect the native installation journal and private data. Recovery never resets users, reruns package removals or silently adopts a live Nginx service.",
        }
    protocol.write_result(args.output, result)
    return 0 if result.get("completed", result.get("healthy", True)) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, PermissionError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
