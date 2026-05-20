#!/usr/bin/env python3
"""
echo: PolyPent reference NDJSON collector (Python).

Phase 4 reference. Reads one JobDescriptor line from stdin, then emits
NDJSON events on stdout per docs/collector-protocol.md:

  hello -> progress -> log -> artifact_ref -> finding -> done

The collector deliberately does no network I/O. It is the executable
specification of the wire contract a third-party collector must follow,
and the platform's first end-to-end exercise of:

  - JobDescriptor parsing
  - NDJSON event emission
  - artifact_ref ingestion (a small text file written to a temp path)
  - finding dedup (re-running produces the same dedup_key)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time


def emit(event_type: str, payload: dict) -> None:
    sys.stdout.write(json.dumps({"type": event_type, "payload": payload}) + "\n")
    sys.stdout.flush()


def main() -> int:
    desc_line = sys.stdin.readline()
    if not desc_line:
        sys.stderr.write("echo: no job descriptor on stdin\n")
        return 2
    desc = json.loads(desc_line)

    target_identity = desc.get("target_identity") or "unknown"
    params = desc.get("parameters") or {}
    steps = int(params.get("steps", 2))

    emit("hello", {
        "name": "echo",
        "version": "0.1.0",
        "protocol_version": desc.get("protocol_version", "polypent-ndjson/1"),
    })
    emit("ack", {"job_id": desc.get("job_id")})

    for i in range(1, steps + 1):
        emit("progress", {"done": i, "total": steps, "stage": f"echo-{i}"})
        emit("log", {"level": "info", "message": f"echo collector step {i}/{steps} for {target_identity}"})
        if params.get("delay_ms"):
            time.sleep(int(params["delay_ms"]) / 1000.0)

    # Emit an artifact_ref pointing at a small file we just wrote. The
    # supervisor will content-hash it and import it into the artifact store.
    fd, path = tempfile.mkstemp(prefix="echo-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f"echo evidence for {target_identity}\n")
        emit("artifact_ref", {"path": path, "mime": "text/plain", "label": "evidence-1"})

        # The finding references that artifact by its label. The supervisor
        # resolves the label to the sha256 it just stored.
        emit("finding", {
            "kind": "info.echo",
            "severity": "informational",
            "title": f"echo saw {target_identity}",
            "description": "Reference Python collector observed the target.",
            # dedup_key is deterministic: re-running this collector for the
            # same target produces the same key, so the platform updates
            # last_seen_at instead of inserting a duplicate.
            "dedup_key": f"echo:saw:{target_identity}",
            "evidence_refs": ["evidence-1"],
        })

        emit("done", {"summary": {"target": target_identity, "steps": steps}})
        # NB: we deliberately leave the temp file on disk. The supervisor
        # has already content-hashed and copied it into the artifact store
        # by the time we get here, but unlinking from this process could
        # race the supervisor's read on slower hosts. A later sweeper
        # garbage-collects orphaned files in TMPDIR.
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
