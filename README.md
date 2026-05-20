# PolyPent

A pentesting platform — not a scanner.

PolyPent owns the durable parts of an engagement (projects, scope, runs,
findings, artifacts, audit) and supervises collectors that do the actual
work. Collectors are replaceable processes; in-tree Go is the default,
external collectors in any language ride a documented NDJSON / JSON-RPC
contract.

## Status

Phases 0–5 are in. Project model, scope engine, queue + worker pool,
NDJSON collector protocol, findings/artifacts, and four in-tree Go
collectors (`http.probe`, `dns.passive`, `tls.inspect`,
`port.tcp.connect`) are all working end-to-end. A reference Python
collector lives under `collectors/python/echo/`.

Phase 6 (polyglot collector examples), Phase 7 (security hardening),
and Phase 8 (web UI) follow.

## Reading order

1. [`docs/architecture.md`](docs/architecture.md) — components, domain
   model, persistence, threat model, repository layout.
2. [`docs/migration-plan.md`](docs/migration-plan.md) — phased build,
   exit criteria, what's explicitly out of scope.
3. [`docs/collector-protocol.md`](docs/collector-protocol.md) — NDJSON
   wire contract for external collectors.
4. [`docs/walkthrough.md`](docs/walkthrough.md) — first engagement
   walkthrough using the CLI.

## Building

```sh
go build ./...
go test -race ./...
golangci-lint run
```

Integration tests run against a Postgres reachable at
`POLYPENT_TEST_DATABASE_URL`; without that env var they skip.

## Binaries

- `cmd/polypentd` — core daemon (`polypentd serve`, `polypentd migrate`,
  `--version`).
- `cmd/polypent` — operator CLI (`polypent project|scope|run|finding ...`,
  `--version`).
