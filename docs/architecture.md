# PolyPent — Architecture

PolyPent is a pentesting platform: a durable system of record for engagements,
not a scanner. It plans, schedules, and supervises tools (collectors); enforces
authorization boundaries (scope); and persists structured evidence (findings,
artifacts) tied to a project and a run.

This document defines the architecture and component boundaries. Implementation
is staged separately in `docs/migration-plan.md`.

## Design principles

1. **API-first.** Every capability is reachable over HTTP before any UI exists.
   The web UI is a later client of the same API operators and CI use.
2. **Scope is a hard constraint, not a convention.** No job runs against an
   asset the project's scope does not permit. Enforcement lives in the core,
   not in collectors.
3. **Collectors are replaceable.** The platform owns scheduling, scope,
   evidence, and provenance. A collector is any process that reads a job and
   emits NDJSON events. In-tree Go is the default; Python and Rust collectors
   ride the same protocol.
4. **Evidence is immutable and addressable.** Findings reference artifacts by
   content hash. A run can be reproduced, audited, and re-graded without
   re-running the collector.
5. **Deterministic boundaries between trusted and untrusted.** The core is
   trusted. Collector output is untrusted input — validated, size-limited, and
   sandboxed before it touches the findings store.
6. **Boring infrastructure.** PostgreSQL for state, filesystem (S3 interface)
   for blobs, a single Go daemon. No Kafka, no Kubernetes operator, no service
   mesh until something concrete demands them.

## Top-level components

```
                     +-------------------+
   operator CLI ---> |                   |
   CI / API client > |   polypentd       | <-- artifact store (fs / S3)
   web UI (later) -> |   (Go daemon)     |
                     |                   | <-- PostgreSQL
                     +---------+---------+
                               | spawns / streams NDJSON over stdio
                               | (or JSON-RPC over a pipe / unix socket)
                               v
                +--------------+--------------+
                |  Collectors                 |
                |  - in-tree Go (linked)      |
                |  - external Go / Py / Rust  |
                |  - third-party tool wrapper |
                +-----------------------------+
```

### `polypentd` — the core daemon

A single Go binary, composed of:

- **API server** — REST + OpenAPI 3.1. JSON over HTTP. Auth via API tokens
  scoped to a project + role. gRPC is *not* a primary interface; it may appear
  later for collector control if NDJSON proves insufficient.
- **Scheduler** — converts a `Run` request into one or more `Job`s, resolves
  the collector binary, clamps targets against project scope, and enqueues.
- **Queue worker pool** — dequeues `Job`s, spawns collectors, supervises
  lifecycle, streams events.
- **Scope engine** — pure library; consulted by the scheduler before
  enqueue and by the worker before exec.
- **Collector registry** — catalog of known collectors: capabilities, input
  schema, output schema, binary path or fetch URL, signature.
- **Findings ingestor** — validates collector NDJSON, normalizes to the
  finding schema, stores artifacts, links them, and writes audit events.
- **Artifact store** — pluggable: local filesystem backend behind an
  S3-shaped interface. Content-addressed (sha256), write-once.
- **Audit log** — append-only record of API calls, job lifecycle, scope
  decisions, and finding mutations. Used for evidence chain-of-custody.

### `polypent` — operator CLI

Thin client of the HTTP API. Used to bootstrap projects, define scope, kick
runs, tail logs, list findings, and pull artifacts. No business logic lives in
the CLI.

### Collectors

A collector is a program that accepts a job descriptor on stdin (or via a CLI
flag pointing at a JSON file) and emits NDJSON events on stdout. The protocol
is detailed in `docs/collector-protocol.md` (to be written in Phase 2).

- **In-tree Go collectors** run in-process for the simple, fast cases (DNS,
  HTTP probe, TLS inspection) and use the same NDJSON event types internally
  so the ingestion path is uniform.
- **External collectors** run as child processes. Python is the right host for
  anything in the offensive-Python ecosystem (impacket, ldap3, scapy at low
  packet rates). Rust is the right host for high-throughput packet/byte work
  (mass-scan-like discovery, custom protocol fuzzers, parsers that need
  predictable memory).
- **Third-party tool wrappers** are collectors whose job is to invoke an
  external binary (e.g. `nmap`, `ffuf`, `nuclei`), translate its native output
  into NDJSON events, and surface its raw output as an artifact.

## Domain model

### Project

The top-level container for an engagement. Carries:

- identity (slug, name, owner, created\_at)
- authorization metadata (rules of engagement document hash, contract window,
  approved contacts)
- scope ruleset (see below)
- secrets vault namespace (per-project credentials, never global)
- retention policy

Every other entity is scoped to exactly one project. There is no global
finding, global target, or cross-project run.

### Scope

A ruleset evaluated as `allow` / `deny` / `out-of-scope`. Rule kinds:

- **Network**: CIDR (v4/v6), single host, ASN, port ranges
- **DNS**: exact name, wildcard (`*.example.com`), suffix
- **HTTP**: URL prefix, path glob, vhost
- **Identity**: account name patterns (for credential-stuffing tests, must be
  explicit and tightly scoped)
- **Time window**: only-during, never-during
- **Rate**: max concurrent requests per host, max requests/sec per host

Rules are *ordered* and *typed*: an explicit deny always beats an implicit
allow. Out-of-scope is distinct from deny — it means "the customer told us
this exists but is excluded"; the platform still records that it was seen and
suppressed, which is useful for the final report.

Scope is evaluated at three points:

1. **Plan time** — when a `Run` is being expanded into `Job`s. Targets that
   resolve out-of-scope are dropped with an audit record.
2. **Dispatch time** — immediately before exec. A target that became
   out-of-scope between plan and dispatch (e.g. ROE expired, time window
   closed) is rejected.
3. **Ingestion time** — a finding whose target is not in scope is quarantined,
   not silently dropped, because that almost always indicates a collector bug
   worth investigating.

### Target

A discovered or seeded asset. Targets carry a kind (`host`, `dns_name`,
`url`, `service`, `account`, `cert`), an identity, a discovery provenance
(which run/finding produced them), and a current scope verdict cached for
display. Targets are unique per `(project, kind, identity)`.

### Collector (catalog entry)

Static metadata describing a collector:

- `name`, `version`, `language`
- `inputs` (JSON Schema for the job payload it accepts)
- `outputs` (which event types and finding kinds it can emit)
- `capabilities` (e.g. `dns.passive`, `http.active`, `tls.inspect`,
  `auth.smb.guess`) — used by the scheduler to match a run plan to collectors
- `binary` (path or content-addressed fetch reference) and signature
- `resource hints` (cpu, memory, network rate)

### Run

A user (or workflow) request: "perform capability set X against target set Y
under this scope, with these parameters". A run is the unit a human reasons
about. It expands into one or more jobs at plan time.

### Job

The unit the worker pool executes. A job binds:

- one collector
- a concrete (already-scope-clamped) target list
- input parameters
- a deadline
- a queue, priority, and resource reservation

Job state machine: `queued → leased → running → (succeeded | failed |
cancelled | timed_out)`. State transitions are logged; restart-on-crash is
explicit, not silent.

### Finding

A structured observation. Fields:

- `project_id`, `run_id`, `job_id`, `collector` (name + version)
- `target` (reference)
- `kind` (e.g. `vuln.cve`, `vuln.misconfig`, `info.banner`, `cred.weak`)
- `severity` (informational / low / medium / high / critical) and optional
  CVSS vector
- `title`, `description`, `evidence_refs` (artifact ids)
- `dedup_key` (deterministic hash so a re-run of the same collector against
  the same target produces idempotent records)
- `status` (new, triaged, accepted, false-positive, remediated)
- `first_seen`, `last_seen`

### Artifact

A content-addressed blob: `sha256:<hex>`. Metadata (mime, size, originating
job, label) is in PostgreSQL; bytes are in the artifact store. Artifacts are
write-once; deletion is a project-retention operation, not a user action.

## Collector protocol (NDJSON)

The default external-collector protocol is line-delimited JSON over stdio.
One JSON object per line, each carrying a `type` discriminator.

Event types (sketch — finalized in Phase 2):

- `hello` — collector announces name, version, and protocol version
- `ack` — acknowledges receipt of the job descriptor
- `progress` — `{ "done": int, "total": int, "stage": str }`
- `log` — structured log line at level (debug/info/warn/error)
- `target.discovered` — proposes a new target for the project; subject to
  scope check on ingestion
- `finding` — full finding payload
- `artifact.begin` / `artifact.chunk` / `artifact.end` — stream a blob
  inline; alternatively `artifact.ref` to point at a file path the worker
  should fingerprint and import
- `error` — recoverable error with context
- `done` — terminal event with a summary

A long-lived or interactive collector (e.g. a credentialed enumerator that
needs to ask "should I pivot here?") uses JSON-RPC 2.0 over the same pipe
instead of one-way NDJSON. The pipe contract is decided per collector at
registration time and surfaced as `protocol: "ndjson" | "jsonrpc"` in the
catalog entry. NDJSON is the default because it's trivial to produce from any
language and trivial to replay from a file.

## Persistence

### PostgreSQL (state of record)

Entities listed above map to tables; relationships are explicit foreign keys.
A few decisions worth pinning now:

- **Queue in Postgres** for v1. `FOR UPDATE SKIP LOCKED` plus `LISTEN/NOTIFY`
  is enough for the throughput pentesting actually requires and removes a
  whole class of "did the broker also durable-store this?" questions.
  Pluggable to NATS/JetStream or Redis Streams later behind a `Queue`
  interface, but only if we have a measured reason.
- **JSONB for collector-specific finding payload extensions** alongside the
  normalized columns. Normalize what the platform reasons about (severity,
  target, dedup\_key); leave the rest queryable but free-form.
- **Migrations** with `golang-migrate`. Forward-only in production; we never
  edit a shipped migration.

### Artifact store

Interface:

```go
type Artifacts interface {
    Put(ctx, reader) (sha256 string, size int64, err error)
    Get(ctx, sha256) (reader, error)
    Stat(ctx, sha256) (size int64, exists bool, err error)
}
```

Backends:

- **Local** — `<data_dir>/artifacts/<aa>/<bb>/<sha256>` (fan-out by hash
  prefix). Default and only required backend for v1.
- **S3-compatible** — same interface, configurable bucket and prefix.

## Security and authorization

- **Token auth.** API tokens are project-scoped and role-scoped
  (`owner`, `operator`, `viewer`, `automation`). No global root token in
  normal operation; the bootstrap token is single-use and rotates on first
  successful API call.
- **Secrets vault.** Per-project encrypted KV (envelope-encrypted with a
  KMS-resident key in production, an on-disk keyfile in dev). Collectors
  receive secrets via the job descriptor; secrets never appear in audit
  events or NDJSON logs (the ingestor scrubs them).
- **Egress containment.** The worker resolves and pins target IPs at dispatch
  time, then runs the collector with that pin (network namespace + nftables
  in the supported Linux deployment; explicit allowlist in dev). A
  compromised collector cannot reach the internet at large or another
  customer's range.
- **Audit chain.** Every API call, every job lifecycle transition, every
  scope decision, every finding mutation lands in `audit_events` with an
  hmac-chained `prev_hash` so tampering is detectable.
- **Provenance.** Each run produces a signed manifest: collector versions,
  scope at run time, target list, finding ids, artifact hashes. The manifest
  is itself an artifact.

## Repository layout (target)

```
/cmd
  /polypentd        # daemon entrypoint
  /polypent         # CLI entrypoint
/internal
  /api              # HTTP handlers, OpenAPI spec generation
  /auth             # tokens, roles, vault
  /scope            # scope engine (pure)
  /project          # project + ROE
  /target           # target store
  /run              # run planner
  /queue            # job queue + worker pool
  /collector        # registry, loader, supervisor
  /protocol/ndjson  # NDJSON codec + event types
  /protocol/jsonrpc # JSON-RPC 2.0 codec
  /finding          # ingestor, dedup, normalization
  /artifact         # store interface + fs/s3 backends
  /audit            # audit log
  /store/postgres   # migrations, queries (sqlc)
  /config           # config loading
  /telemetry        # logging, metrics, tracing
/collectors
  /go               # in-tree Go collectors
  /python           # reference Python collectors (separate venv)
  /rust             # reference Rust collectors (separate Cargo workspace)
/api                # OpenAPI spec, generated clients
/migrations         # SQL migrations
/deploy             # systemd unit, container, sample configs
/docs
```

The Python and Rust trees are separate build systems on purpose. They're
allowed to exist; they're not allowed to be load-bearing for the core.
Removing the entire `collectors/python` directory must leave a working
platform.

## Out of scope for v1

Recorded here so they don't accidentally creep in:

- multi-tenant SaaS hosting (single-tenant self-host first)
- attack-path graphing / BloodHound-style analysis
- exploit-as-a-service / automated exploitation
- LLM-driven triage (the data model should support it later; we don't build
  it now)
- the web UI

## Open questions

These need a decision before the corresponding phase starts; they don't block
Phase 0.

1. **Workflow language.** Do runs compose collectors via a declarative DAG
   (YAML), via code (Go-defined workflows), or both? Leaning declarative for
   v1 because pentest playbooks are the natural unit.
2. **Distributed workers.** Single-node daemon is fine for v1. Do we design
   the queue lease protocol now to be multi-node-safe (yes — `SKIP LOCKED`
   already is), or do we go further and design worker registration / health?
3. **Finding schema source of truth.** Hand-written Go structs + JSON
   Schema, or schema-first with code generation? Leaning schema-first
   because external collectors need the schema anyway.
4. **Sandboxing collectors.** nsjail vs. firecracker vs. plain user namespace
   + nftables. The interface is the same; the choice affects deploy
   complexity.
