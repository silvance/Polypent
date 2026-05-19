# PolyPent — Migration / Build Plan

"Migration" here means the staged build from an empty repository to a usable
platform. Each phase has an exit criterion that is demonstrable, not
aspirational. Nothing in a later phase may be relied on by an earlier phase.

The plan is sequenced so that scope enforcement, evidence durability, and the
collector contract are working before any real collector ships. The risk we
are managing is shipping a tool that runs commands against the internet
without the platform around it being trustworthy.

## Phase 0 — Foundations (no behavior, scaffolding only)

**Goal:** a buildable Go module, CI, lint, and the docs that define the
contract. No business logic.

- `go.mod`, module path `github.com/silvance/polypent`
- `cmd/polypentd` and `cmd/polypent` with `--version` and nothing else
- Linting: `golangci-lint` with a curated config; `gofmt`, `govet`,
  `staticcheck`, `errcheck`, `gosec`
- Testing: `go test ./...` green; race detector on
- CI: a single GitHub Actions workflow that runs build + lint + test on push
  and PR. No deploy steps.
- License + `CODEOWNERS` + security policy stub
- Docs: this file and `architecture.md` (done). Begin `collector-protocol.md`
  as a stub that will be filled in Phase 2.

**Exit criterion:** `go build ./...`, `go test ./...`, and `golangci-lint run`
all succeed in CI on a fresh clone.

## Phase 1 — Persistence, config, and the project model

**Goal:** the daemon boots, connects to Postgres, owns a config file, and can
CRUD projects via the API.

- Configuration loader (`internal/config`): YAML + env overrides; explicit
  errors on unknown keys
- Postgres driver (`pgx`) and migration runner (`golang-migrate`)
- Initial migrations: `projects`, `audit_events`, `api_tokens`
- `internal/api`: HTTP server with structured logging, request ids, panic
  recovery, graceful shutdown
- Auth middleware: bearer token → project + role
- Endpoints: `POST /v1/projects`, `GET /v1/projects`, `GET /v1/projects/{id}`,
  `PATCH /v1/projects/{id}`, token creation
- Audit log writer with hmac-chained `prev_hash`
- OpenAPI spec: hand-written for now, served at `/openapi.json`; we'll
  decide schema-first vs. code-first in Phase 4 when collectors need it

**Exit criterion:** an integration test creates a project, lists it, mutates
it, and asserts the corresponding audit events are present and chained.

## Phase 2 — Scope engine and target store

**Goal:** scope is a first-class, tested, library-level concern before any job
runs.

- `internal/scope`: pure library. Rule types per the architecture doc.
  Evaluator returns one of `allow`, `deny`, `out_of_scope` with the rule that
  decided.
- Property-based tests for the engine: monotonicity (adding a deny never
  turns deny into allow), ordering (explicit deny beats implicit allow),
  determinism (same inputs → same verdict + same rule id).
- Migrations: `scope_rules`, `targets`, `target_provenance`
- API: scope CRUD, target list, scope simulation endpoint
  (`POST /v1/projects/{id}/scope/check` — "would this target be allowed?")
- CLI: `polypent scope add|list|check`

**Exit criterion:** scope simulation endpoint covers a real engagement's
ruleset (IPv4 + IPv6 + DNS wildcard + time window + rate cap) and the
property tests pass under `-race -count=50`.

## Phase 3 — Run / Job queue, no real collectors yet

**Goal:** a working queue with a worker pool and a mock collector. Lifecycle,
leasing, cancellation, and timeouts are all exercised before any tool runs.

- Migrations: `runs`, `jobs`, `job_events`
- `internal/queue`: Postgres-backed queue using `FOR UPDATE SKIP LOCKED`,
  `LISTEN/NOTIFY` for wake-up. `Queue` interface designed so a non-Postgres
  backend is possible later but not built.
- `internal/run`: planner that turns a run request into jobs after
  scope-clamping the target list
- Worker pool with bounded concurrency, per-job context with deadline,
  cancellation propagation, graceful shutdown drain
- Built-in `mock` collector (in-tree Go) that emits a scripted NDJSON
  sequence: progress, log, two findings, done — used by the queue tests
- API: `POST /v1/projects/{id}/runs`, `GET /v1/runs/{id}`,
  `GET /v1/runs/{id}/jobs`, `POST /v1/runs/{id}/cancel`

**Exit criterion:** chaos test — start 50 runs across 3 projects with a
worker pool of 8, kill workers mid-flight, verify no job is lost, no job is
double-completed, and the audit log reconstructs the truth.

## Phase 4 — Collector protocol, registry, and the ingestor

**Goal:** lock the external collector contract. Stand up the in-process
ingestor. After this phase, adding a new collector is a contained activity.

- `docs/collector-protocol.md` finalized: NDJSON event types, error model,
  JSON Schema for each event, JSON-RPC variant for interactive collectors
- `internal/protocol/ndjson`: encoder, decoder, validator
- `internal/protocol/jsonrpc`: minimal JSON-RPC 2.0 codec
- `internal/collector`: registry (catalog) with capability matching;
  supervisor that spawns a child process, pipes the job descriptor on stdin,
  parses events on stdout, captures stderr as a log artifact, enforces
  timeouts, kills the process group on cancel
- `internal/finding`: validator, dedup, normalization
- Migrations: `collectors_catalog`, `findings`, `artifacts`
- Artifact store: local fs backend behind the `Artifacts` interface;
  content-addressed write; idempotent
- API: collector catalog CRUD, finding list/filter, artifact download
- Decide schema-first vs. hand-written here, now that external languages
  consume the schema

**Exit criterion:** a Python reference collector (≈100 lines) registered via
the catalog, invoked through a run, emits findings and an artifact, and the
findings appear via the API with correct dedup behavior on a re-run.

## Phase 5 — First useful Go collectors

**Goal:** prove the platform with collectors that solve real problems and
that exist precisely because Go is appropriate for them.

In-tree Go collectors:

- `dns.passive` — bulk DNS resolution with rate-limited concurrent lookups
- `http.probe` — HTTP/1.1 + HTTP/2 probe, capture headers + TLS chain
- `tls.inspect` — full handshake + cert chain + protocol/cipher matrix
- `port.tcp.connect` — bounded TCP connect scan with per-host rate caps
  pulled from scope

Each ships with: capability declaration, input schema, output schema (which
finding kinds it emits), integration tests using a local fixture target, and
documentation.

**Exit criterion:** a documented "first engagement" walkthrough — `polypent
project create`, `scope add`, `run --capabilities ...`, `findings list` —
that works end-to-end against a sample target in CI.

## Phase 6 — Polyglot collectors where they earn it

**Goal:** demonstrate that Python and Rust collectors are first-class without
making them load-bearing.

- Python: `smb.enum` (impacket) and `ldap.enum` (ldap3) reference collectors
  with their own pyproject and CI lane
- Rust: `discover.tcp.syn` reference collector for high-throughput discovery,
  in a separate Cargo workspace under `collectors/rust`
- Third-party wrapper template: a Go collector that shells out to `nmap`,
  parses its XML, and emits normalized findings + the raw XML as an artifact

Each must pass the same conformance test suite the Go collectors pass; that
suite is the executable definition of the protocol.

**Exit criterion:** the conformance suite passes for collectors in all three
languages and for one third-party wrapper.

## Phase 7 — Security hardening

**Goal:** the things from "Security and authorization" in the architecture
that were stubbed earlier are now real.

- Per-project secrets vault with envelope encryption
- Egress containment for the supported Linux deployment (network namespace +
  nftables target-pin)
- Signed run manifests
- Token rotation, expiry, and revocation lists
- Threat model document; a written "what an attacker who steals a collector
  binary can do" analysis

**Exit criterion:** a red-team exercise where a deliberately malicious
collector is loaded; we verify it cannot reach an out-of-scope host, cannot
exfiltrate via DNS, cannot read another project's secrets, and is detected by
audit events.

## Phase 8 — Web UI

Begins only when Phases 0–6 are merged and Phase 7 is in progress. UI is a
client of the existing API; no API endpoint is added solely because the UI
wants it without first justifying it for CLI/automation use.

## Sequencing rules

- No collector ships before Phase 4 (the protocol is the contract).
- No real network activity ships before Phase 2 (scope is the safety belt).
- No multi-node deployment ships before Phase 7 (auth + audit need to be
  honest first).
- Migrations are forward-only from Phase 1 onward. If a migration ships and
  is wrong, the fix is a new migration.

## What we are explicitly not doing

- A scanner that's a thin wrapper around `nmap` + `nuclei` and calls itself a
  platform. We're building the platform; those tools can ride on it as
  collectors.
- A vendored copy of every offensive tool. The collector contract makes
  vendoring unnecessary.
- A reporting engine in v1. Findings + artifacts + run manifests are the
  inputs to a report; the report is downstream and out of scope for v1.

## Risks worth naming

1. **Scope drift in collectors.** A collector that "helpfully" follows a
   redirect off-scope is a real incident. Mitigation: the worker, not the
   collector, opens the network. Collectors receive resolved, pinned target
   descriptors and ride a namespace they can't escape.
2. **NDJSON ambiguity.** Hand-written event schemas drift. Mitigation: pick
   schema-first in Phase 4 and generate the validator on both sides from the
   same source.
3. **Postgres queue at scale.** It's fine until it isn't. Mitigation: the
   `Queue` interface is narrow enough to swap. We don't pre-build the swap.
4. **Polyglot tax.** Three build systems is expensive. Mitigation: the Python
   and Rust trees stay optional and the CI lane for each is separable. The
   core never imports them.
