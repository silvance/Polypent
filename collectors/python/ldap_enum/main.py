#!/usr/bin/env python3
"""
ldap_enum: PolyPent reference LDAP enumerator (Python).

Reads one JobDescriptor on stdin, emits NDJSON on stdout per
docs/collector-protocol.md.

Target: kind=host, identity=<host>[:<port>] (defaults to 389).

When `ldap3` is importable, performs an anonymous bind and dumps the
naming contexts. Otherwise falls back to a "dry run" structural
emission so the platform's conformance suite still passes and
operators without ldap3 get a sane error path.
"""
from __future__ import annotations

import json
import socket
import sys
from typing import Any

try:
    from ldap3 import Server, Connection, ALL, ANONYMOUS  # type: ignore
    HAS_LDAP3 = True
except Exception:
    HAS_LDAP3 = False


def emit(event_type: str, payload: dict) -> None:
    sys.stdout.write(json.dumps({"type": event_type, "payload": payload}) + "\n")
    sys.stdout.flush()


def split_host_port(identity: str, default_port: int = 389) -> tuple[str, int]:
    if ":" in identity and not identity.endswith("]"):
        h, _, p = identity.rpartition(":")
        try:
            return h, int(p)
        except ValueError:
            pass
    return identity, default_port


def dry_run(host: str, port: int) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=2.0):
            reachable = True
    except OSError:
        reachable = False
    return {"reachable": reachable, "mode": "dry-run", "reason": "ldap3 not installed"}


def real_probe(host: str, port: int) -> dict[str, Any]:
    srv = Server(host, port=port, get_info=ALL, connect_timeout=5)
    conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
    try:
        info = srv.info
        if info is None:
            return {"mode": "live", "naming_contexts": [], "vendor_name": None}
        return {
            "mode": "live",
            "naming_contexts": list(info.naming_contexts or []),
            "vendor_name": getattr(info, "vendor_name", None),
            "vendor_version": getattr(info, "vendor_version", None),
            "supported_ldap_versions": list(getattr(info, "supported_ldap_versions", []) or []),
        }
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def main() -> int:
    line = sys.stdin.readline()
    if not line:
        sys.stderr.write("ldap_enum: no job descriptor on stdin\n")
        return 2
    desc = json.loads(line)
    if desc.get("target_kind") != "host":
        sys.stderr.write(f"ldap_enum: unsupported target_kind {desc.get('target_kind')!r}\n")
        return 2
    host, port = split_host_port(desc.get("target_identity") or "")
    if not host:
        sys.stderr.write("ldap_enum: empty target\n")
        return 2

    emit("hello", {"name": "ldap_enum", "version": "0.1.0",
                   "protocol_version": desc.get("protocol_version", "polypent-ndjson/1")})
    emit("ack", {"job_id": desc.get("job_id")})

    emit("progress", {"done": 1, "total": 2, "stage": "connect"})
    try:
        if HAS_LDAP3:
            info = real_probe(host, port)
        else:
            info = dry_run(host, port)
    except Exception as e:  # noqa: BLE001
        emit("error", {"message": f"probe error: {e}", "fatal": False})
        info = {"mode": "error", "reason": str(e)}

    emit("progress", {"done": 2, "total": 2, "stage": "report"})

    severity = "informational"
    title = f"LDAP enumeration of {host}:{port}"
    if info.get("mode") == "live" and info.get("naming_contexts"):
        # Anonymous bind that returns naming contexts is information
        # disclosure worth highlighting.
        severity = "low"
        title = f"LDAP anonymous bind discloses {len(info['naming_contexts'])} naming context(s) at {host}:{port}"

    emit("finding", {
        "kind": "info.ldap.enum",
        "severity": severity,
        "title": title,
        "description": json.dumps(info, sort_keys=True, default=str),
        "dedup_key": f"ldap_enum:host:{host}:{port}",
        "extra": info,
    })

    emit("done", {"summary": {"target": f"{host}:{port}", "mode": info.get("mode")}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
