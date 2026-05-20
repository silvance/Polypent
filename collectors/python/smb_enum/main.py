#!/usr/bin/env python3
"""
smb_enum: PolyPent reference SMB enumerator (Python).

Reads one JobDescriptor on stdin, emits NDJSON on stdout per
docs/collector-protocol.md.

Target: kind=host, identity=<host>[:<port>].

If `impacket` is importable, performs a real SMB negotiate via
impacket.smbconnection. Otherwise the collector falls back to a
structural "dry run" so the platform's conformance suite (and any
operator without impacket) still gets a clean lifecycle:

  hello -> ack -> progress -> finding -> done

The finding's dedup_key is deterministic per (host, kind) so re-runs
refresh existing rows instead of duplicating.
"""
from __future__ import annotations

import json
import socket
import sys
from typing import Any

try:
    from impacket.smbconnection import SMBConnection  # type: ignore
    HAS_IMPACKET = True
except Exception:  # ImportError or any side-effect of importing
    HAS_IMPACKET = False


def emit(event_type: str, payload: dict) -> None:
    sys.stdout.write(json.dumps({"type": event_type, "payload": payload}) + "\n")
    sys.stdout.flush()


def split_host_port(identity: str, default_port: int = 445) -> tuple[str, int]:
    if ":" in identity and not identity.endswith("]"):
        h, _, p = identity.rpartition(":")
        try:
            return h, int(p)
        except ValueError:
            pass
    return identity, default_port


def dry_run(host: str, port: int) -> dict[str, Any]:
    """Best-effort port reachability check using stdlib only."""
    open_445 = False
    try:
        with socket.create_connection((host, port), timeout=2.0):
            open_445 = True
    except OSError:
        open_445 = False
    return {"reachable": open_445, "mode": "dry-run", "reason": "impacket not installed"}


def real_probe(host: str, port: int) -> dict[str, Any]:
    """Real SMB negotiate; only invoked when impacket is importable."""
    conn = SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=5)
    try:
        info = {
            "mode": "live",
            "server_os": conn.getServerOS(),
            "server_domain": conn.getServerDomain(),
            "server_name": conn.getServerName(),
            "dialect": conn.getDialect(),
            "signing_required": conn.isSigningRequired(),
        }
    finally:
        try:
            conn.logoff()
        except Exception:  # noqa: BLE001
            pass
    return info


def main() -> int:
    line = sys.stdin.readline()
    if not line:
        sys.stderr.write("smb_enum: no job descriptor on stdin\n")
        return 2
    desc = json.loads(line)
    if desc.get("target_kind") != "host":
        sys.stderr.write(f"smb_enum: unsupported target_kind {desc.get('target_kind')!r}\n")
        return 2
    host, port = split_host_port(desc.get("target_identity") or "")
    if not host:
        sys.stderr.write("smb_enum: empty target\n")
        return 2

    emit("hello", {"name": "smb_enum", "version": "0.1.0",
                   "protocol_version": desc.get("protocol_version", "polypent-ndjson/1")})
    emit("ack", {"job_id": desc.get("job_id")})

    emit("progress", {"done": 1, "total": 2, "stage": "connect"})
    try:
        if HAS_IMPACKET:
            info = real_probe(host, port)
        else:
            info = dry_run(host, port)
    except Exception as e:  # noqa: BLE001
        emit("error", {"message": f"probe error: {e}", "fatal": False})
        info = {"mode": "error", "reason": str(e)}

    emit("progress", {"done": 2, "total": 2, "stage": "report"})

    severity = "informational"
    title = f"SMB enumeration of {host}:{port}"
    if info.get("mode") == "live" and info.get("signing_required") is False:
        # SMB signing disabled is a real finding.
        severity = "medium"
        title = f"SMB signing NOT required at {host}:{port}"

    emit("finding", {
        "kind": "info.smb.enum",
        "severity": severity,
        "title": title,
        "description": json.dumps(info, sort_keys=True),
        # dedup_key is independent of the live/dry-run mode so a
        # re-run with impacket added doesn't duplicate the row.
        "dedup_key": f"smb_enum:host:{host}:{port}",
        "extra": info,
    })

    emit("done", {"summary": {"target": f"{host}:{port}", "mode": info.get("mode")}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
