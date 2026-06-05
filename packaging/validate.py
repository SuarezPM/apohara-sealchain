#!/usr/bin/env python3
"""Structural lint for the packaging manifests (stdlib only).

Loads mcp.json + plugin.json and asserts the required keys/shape documented in
SCHEMAS.md. Exits non-zero on the first failure. This is the structural-lint
stand-in for a formal JSON-Schema validator.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def fail(msg: str) -> None:
    print(f"validate.py: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def load(name: str) -> dict:
    path = HERE / name
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        fail(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"{name}: invalid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{name}: top-level value must be an object")
    return data


def check_mcp_servers(name: str, servers: object) -> None:
    if not isinstance(servers, dict) or not servers:
        fail(f"{name}: 'mcpServers' must be a non-empty object")
    for server_name, entry in servers.items():
        where = f"{name}: mcpServers.{server_name}"
        if not isinstance(entry, dict):
            fail(f"{where}: must be an object")
        command = entry.get("command")
        if not isinstance(command, str) or not command:
            fail(f"{where}: 'command' must be a non-empty string")
        args = entry.get("args")
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            fail(f"{where}: 'args' must be an array of strings")


def validate_mcp() -> None:
    name = "mcp.json"
    data = load(name)
    if "mcpServers" not in data:
        fail(f"{name}: missing required key 'mcpServers'")
    check_mcp_servers(name, data["mcpServers"])


def validate_plugin() -> None:
    name = "plugin.json"
    data = load(name)
    for key in ("name", "version", "description"):
        value = data.get(key)
        if not isinstance(value, str) or not value:
            fail(f"{name}: '{key}' must be a non-empty string")
    if "mcpServers" not in data:
        fail(f"{name}: missing required key 'mcpServers'")
    check_mcp_servers(name, data["mcpServers"])


def main() -> None:
    validate_mcp()
    validate_plugin()
    print("validate.py: OK (mcp.json + plugin.json passed structural lint)")


if __name__ == "__main__":
    main()
