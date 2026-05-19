# PolyPent

A pentesting platform — not a scanner.

PolyPent owns the durable parts of an engagement (projects, scope, runs,
findings, artifacts, audit) and supervises collectors that do the actual
work. Collectors are replaceable processes; in-tree Go is the default,
external collectors in any language ride a documented NDJSON / JSON-RPC
contract.

## Status

Phase 0 — scaffolding. The repo builds, tests, and lints cleanly. Neither
binary does any real work yet.

See:

- [`docs/architecture.md`](docs/architecture.md) — components, domain
  model, persistence, security model.
- [`docs/migration-plan.md`](docs/migration-plan.md) — phased build with
  exit criteria.
- [`docs/collector-protocol.md`](docs/collector-protocol.md) — collector
  contract (stub; finalized in Phase 4).

## Building

```sh
go build ./...
go test -race ./...
golangci-lint run
```

## Binaries

- `cmd/polypentd` — core daemon.
- `cmd/polypent`  — operator CLI.

Both currently accept `--version` and nothing else.
