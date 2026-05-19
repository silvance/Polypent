# PolyPent Collector Protocol

> **Status:** stub. Finalized in Phase 4 of `migration-plan.md`. This file
> exists in Phase 0 only to reserve the contract surface and to record
> decisions as they accrete.

## Purpose

The collector protocol is the boundary between the trusted PolyPent core
(`polypentd`) and untrusted collector processes. Pinning the wire format
before any real collector is written means:

- A collector author has a single, authoritative specification to target.
- The core can ingest collector output without language-specific glue.
- A failing collector can be replayed offline from captured NDJSON.

## Default transport: NDJSON over stdio

The default is line-delimited JSON. One JSON object per line, UTF-8, `\n`
terminated, no embedded newlines, soft cap on line length (TBD in Phase 4).

The collector reads its job descriptor from stdin as a single JSON object
followed by `EOF` on stdin (or as a single NDJSON line, TBD). It emits
events on stdout. stderr is captured by the worker as a log artifact and
must not be parsed as protocol traffic.

### Event types (provisional)

| `type`               | Direction        | Purpose                                    |
|----------------------|------------------|--------------------------------------------|
| `hello`              | collector → core | Announce name, version, protocol version   |
| `ack`                | collector → core | Acknowledge job descriptor                 |
| `progress`           | collector → core | `{done, total, stage}`                     |
| `log`                | collector → core | Structured log line                        |
| `target.discovered`  | collector → core | Propose a new target (subject to scope)    |
| `finding`            | collector → core | Full finding payload                       |
| `artifact.begin`     | collector → core | Begin streaming a blob                     |
| `artifact.chunk`     | collector → core | Blob chunk (base64)                        |
| `artifact.end`       | collector → core | Finalize a blob                            |
| `artifact.ref`       | collector → core | Reference an on-disk file to import        |
| `error`              | collector → core | Recoverable error with context             |
| `done`               | collector → core | Terminal event with summary                |

The JSON Schema for each event is a Phase 4 deliverable.

## Alternative transport: JSON-RPC 2.0

For interactive collectors (e.g. credentialed enumerators that must ask
the core questions mid-run), JSON-RPC 2.0 rides the same stdio pipe in
place of NDJSON. The transport choice is declared at registration time
in the collector catalog entry (`protocol: "ndjson" | "jsonrpc"`).

The JSON-RPC method set is a Phase 4 deliverable.

## Conformance

A language-agnostic conformance suite ships in Phase 6. Every collector —
in-tree Go, external Python, external Rust, third-party tool wrapper —
must pass the same suite. The suite is the executable definition of this
spec; where the suite and this prose disagree, the suite wins, and the
prose is corrected.

## Non-goals

- Bidirectional streaming of arbitrary protobufs. NDJSON is sufficient
  for the workloads PolyPent actually has.
- gRPC as a primary collector transport. Reconsidered only if NDJSON +
  JSON-RPC are shown empirically insufficient.
