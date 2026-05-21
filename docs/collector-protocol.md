# PolyPent Collector Protocol

**Status:** Phase 4 stabilization. The on-wire format defined here is the
contract collectors must follow; behavior changes ship via a bumped
`protocol_version` string. The reference Python collector in
`collectors/python/echo/` is the executable specification.

## Why a protocol exists

PolyPent's core (`polypentd`) owns scope, scheduling, evidence, and audit.
Collectors do the actual work. The protocol is the boundary: the core
never trusts a collector beyond what the protocol says it can do, and a
collector never reasons about projects or scope beyond what the
`JobDescriptor` hands it.

## Wire transports

### Default: NDJSON over stdio

- One JSON object per line, UTF-8, terminated by `\n`.
- Lines must be at most `1 MiB`. The supervisor enforces the cap and
  treats over-length lines as a fatal protocol error.
- The supervisor writes a single line on stdin — the `JobDescriptor` —
  and then closes stdin. The collector emits events on stdout. Anything
  on stderr is captured by the supervisor as a `log` event and the
  collector should not depend on it for protocol traffic.

### Alternative: JSON-RPC 2.0

Reserved for interactive collectors that need to ask the core questions
mid-run (e.g. a credentialed enumerator deciding whether to pivot). The
catalog entry's `transport` field selects which one a collector uses.
JSON-RPC over the same stdio pipe ships in a later phase; collectors
shipping in Phase 4 use NDJSON.

## Job descriptor

The supervisor writes exactly one of these as the first line on the
collector's stdin:

```json
{
  "job_id": "uuid",
  "run_id": "uuid",
  "project_id": "uuid",
  "collector": "echo",
  "target_kind": "host",
  "target_identity": "10.0.0.5",
  "parameters": { "...": "..." },
  "deadline_unix_sec": 1717891200,
  "protocol_version": "polypent-ndjson/1"
}
```

The target has already been scope-clamped at plan time and at dispatch
time. **A collector MUST NOT range beyond the listed target.** Sending
findings about other targets is treated as a scope violation: the finding
is quarantined and an audit event is raised.

## Events

Every event is a single JSON object with a discriminator field `type`
and an optional `payload`. The supervisor records the raw line in
`job_events` regardless of whether the platform separately ingests it.

| `type`              | Direction        | Required fields                                   |
|---------------------|------------------|---------------------------------------------------|
| `hello`             | collector → core | `name`, `version`, `protocol_version`             |
| `ack`               | collector → core | `job_id`                                          |
| `progress`          | collector → core | `done`, `total`; optional `stage`                 |
| `log`               | collector → core | `level`, `message`; optional `fields`             |
| `target_discovered` | collector → core | `kind`, `identity`                                |
| `artifact_ref`      | collector → core | `path`; optional `mime`, `label`                  |
| `finding`           | collector → core | `kind`, `severity`, `title`, `dedup_key`          |
| `error`             | collector → core | `message`; optional `code`, `fatal`               |
| `done`              | collector → core | optional `summary`                                |

### `finding`

```json
{
  "type": "finding",
  "payload": {
    "kind": "info.echo",
    "severity": "informational",
    "title": "echo saw 10.0.0.5",
    "description": "Reference Python collector observed the target.",
    "dedup_key": "echo:saw:10.0.0.5",
    "evidence_refs": ["evidence-1"],
    "cvss": "",
    "extra": {}
  }
}
```

- **`dedup_key`** is the collector's deterministic identity for the
  finding. Re-running the same collector against the same target with
  the same finding MUST produce the same `dedup_key`. The core uses
  `(project_id, collector, dedup_key)` as the unique key: a re-emit
  refreshes `last_seen_at`, severity, description, evidence, and the
  associated run/job, but does not produce a second row.
- **`evidence_refs`** are labels the collector used in earlier
  `artifact_ref` events within the same job. The supervisor resolves
  each label to the sha256 it computed when it ingested the file. If a
  ref is already a 64-char hex string, the supervisor treats it as an
  existing artifact sha and links it as-is.
- **`severity`** is one of `informational`, `low`, `medium`, `high`,
  `critical`.

### `artifact_ref`

```json
{
  "type": "artifact_ref",
  "payload": {
    "path": "/tmp/echo-12345.txt",
    "mime": "text/plain",
    "label": "evidence-1"
  }
}
```

The supervisor opens `path`, hashes the contents into the content-
addressed store, and records the metadata. The path must be readable by
the polypentd process. Phase 4 deliberately does not stream artifacts
inline (`artifact.begin/chunk/end`); the smallest workable shape carries
us until a collector actually needs streaming.

The collector MUST NOT delete the referenced file before emitting `done`,
because the supervisor reads it lazily from the same goroutine that
processes the event stream.

## Error model

- `error` with `"fatal": true` requires the collector to exit non-zero
  after emitting it.
- `error` with `"fatal": false` is a recoverable error report; the
  collector continues.
- A non-zero exit without an `error` or `done` event is treated as a job
  failure with the exit error as the message.

## Conformance

`collectors/python/echo/main.py` is the reference implementation. The
Phase 4 integration test (`internal/api/integration_phase4_test.go`)
runs the reference collector end-to-end through the supervisor, verifies:

- the descriptor parses,
- progress/log/artifact_ref/finding/done all appear in `job_events`,
- the referenced file lands in the artifact store and is downloadable
  via `GET /v1/artifacts/{sha}`,
- a re-run with the same target produces no new finding row (dedup) but
  advances `last_seen_at`.

A future Phase 6 conformance suite will codify this for Python, Go, Rust,
and third-party wrappers in a way the supervisor can run against any
catalog entry on demand.
