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
    fields = [
        {
            "key": "role",
            "label": "Role: controller, agent or combined",
            "type": "string",
            "required": True,
            "default": "combined",
        },
        {
            "key": "public_url",
            "label": "Management HTTPS origin (controller/combined)",
            "type": "string",
            "required": False,
        },
        {
            "key": "fleet_url",
            "label": "Fleet HTTPS origin (controller/combined)",
            "type": "string",
            "required": False,
        },
        {
            "key": "email",
            "label": "Initial owner email (controller/combined)",
            "type": "string",
            "required": False,
        },
        {
            "key": "name",
            "label": "Initial owner name (controller/combined)",
            "type": "string",
            "required": False,
        },
        {
            "key": "password_file",
            "label": "Owner password file (controller/combined)",
            "type": "string",
            "required": False,
            "secret": True,
        },
        {
            "key": "controller",
            "label": "Controller HTTPS origin (agent)",
            "type": "string",
            "required": False,
        },
        {
            "key": "enrollment_token_file",
            "label": "Enrollment token file (agent)",
            "type": "string",
            "required": False,
            "secret": True,
        },
        {
            "key": "ca_file",
            "label": "Verified fleet CA file (agent)",
            "type": "string",
            "required": False,
            "secret": True,
        },
        {
            "key": "ca_sha256",
            "label": "Fleet CA SHA256 (agent)",
            "type": "string",
            "required": False,
        },
        {
            "key": "management_bind",
            "label": "Management bind",
            "type": "string",
            "required": False,
            "default": "127.0.0.1:9443",
        },
        {
            "key": "fleet_bind",
            "label": "Fleet bind",
            "type": "string",
            "required": False,
            "default": "0.0.0.0:9444",
        },
        {
            "key": "behind_proxy",
            "label": "Existing HTTPS management frontend (true/false)",
            "type": "boolean",
            "required": False,
            "default": False,
        },
        {
            "key": "package_removal",
            "label": "Enable guarded package removal (true/false)",
            "type": "boolean",
            "required": False,
            "default": False,
        },
    ]
    if not request.get("configuration"):
        system = native.platform.freedesktop_os_release()
        state = {
            "supported": (system.get("ID"), system.get("VERSION_ID"))
            in (("ubuntu", "24.04"), ("debian", "13"))
            and native.platform.machine() in ("x86_64", "aarch64"),
            "ready_for_apply": False,
            "configuration": {},
            "manual_steps": ["Complete role-specific configuration before review"],
            "configuration_fields": fields,
        }
    else:
        state = native.inspect(request.get("configuration", {}), SOURCE)
        state["configuration_fields"] = fields
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
        result["health"]["ok"] = result["health"]["healthy"]
        if not result["health"]["healthy"]:
            result.update(completed=False, state="needs_recovery")
    elif args.action in ("status", "health"):
        status = native.health()
        result = {**status, "health": {**status, "ok": status.get("healthy", False)}}
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
