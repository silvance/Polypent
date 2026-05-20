# PolyPent Threat Model

**Status:** Phase 7 working document. Updated as mitigations land. This
is the platform's own threat model — not the threat model of a system
under test, which lives in the engagement's project metadata.

## What the platform protects

| Asset                       | Why it matters                                                |
|-----------------------------|---------------------------------------------------------------|
| Audit signing key           | Forging audit chain entries; forging run manifests            |
| API tokens                  | Direct authorization to act under a role                      |
| Project secrets vault       | Credentials the operator handed PolyPent; future Phase 7      |
| Scope rules                 | Authority boundary; tampering = unauthorized testing          |
| Findings + artifacts        | Evidence; chain of custody for the engagement report          |
| Audit log                   | After-the-fact accountability                                 |
| Run manifests               | Signed evidence bundle handed to auditors / customers         |
| Collector binaries          | Trusted code path — a swapped binary is a swapped contract    |

## Trust boundaries

```
operator -----A----- API ----B---- polypentd ---C--- DB / artifact store
                                       |
                                       D
                                       |
                                  collector(s)
                                       |
                                       E
                                       |
                                   target system
```

- **A. operator ↔ API**: untrusted network. Bearer-token auth over TLS
  in production. Currently TLS termination is out-of-band (reverse
  proxy in front of `polypentd serve`); Phase 7+ will own TLS directly.
- **B. API ↔ polypentd**: same process today; this boundary becomes
  meaningful only if/when we split workers from the API server. The
  Queue interface is already narrow enough to do that.
- **C. polypentd ↔ Postgres / artifact FS**: trusted storage. Postgres
  connection string carries credentials; artifact filesystem is
  permissioned to the polypentd user. No tenant data flows over this
  boundary that the daemon hasn't already validated.
- **D. polypentd ↔ collector**: the one boundary the platform treats as
  fully untrusted. See "Collector threat model" below.
- **E. collector ↔ target system**: the actual engagement boundary;
  scope rules define what's permitted to cross it.

## Threats and mitigations

### T1 — Stolen API token

*Threat*: an attacker exfiltrates a bearer token (laptop theft,
copy-paste into a log, leaked env var).

*Mitigations in place (Phase 1, 7)*:
- Tokens are 32-byte high-entropy random strings; the database stores
  only sha256(token).
- Per-project, per-role scoping limits blast radius.
- `POST /v1/tokens/{id}/revoke` revokes immediately, audited.
- `expires_at` is honored on every lookup.
- Audit log records the actor token id on every mutation, so a
  retroactive review can answer "what did this token do?"

*Gaps*:
- Tokens are presented as bearer credentials. We don't yet support
  request-binding (DPoP-style proof-of-possession) — exfiltration is
  fully usable until revoked.
- We do not yet automatically rotate or warn on long-lived tokens.

### T2 — Malicious or compromised collector

*Threat*: a collector binary writes arbitrary files, makes
out-of-scope network calls, exfiltrates secrets from the host.

*Mitigations in place (Phase 4)*:
- External collectors run as child processes in their own process
  group; the supervisor reaps the whole group on cancel/error.
- stderr is captured into a capped buffer (1 MiB) and emitted as a
  `log` event, so a malicious collector cannot silently exhaust memory
  via stderr.
- NDJSON line cap (1 MiB) bounds per-event memory.
- The collector receives a JobDescriptor naming exactly one target;
  any finding emitted against a different target is quarantined at
  ingest (Phase 7 extends the in-process worker to enforce this).
- Artifact paths must be sha256-shaped before any Open(); path
  traversal via the API surface is impossible.

*Gaps (Phase 7 work in progress)*:
- No network namespace / nftables egress containment. A compromised
  collector running on the polypentd host CAN reach the wider
  internet today. This is the single biggest gap.
- No mandatory binary signature check on catalog upsert; an admin
  token + filesystem write are sufficient to swap collectors. Phase 7
  will require a signed catalog entry whose signature is verified at
  load time.
- No CPU / memory cgroup. A run-away collector can starve the host.

### T3 — Scope drift / unauthorized testing

*Threat*: a collector probes a target that the customer did not
authorize, either by accident (a redirect, a CNAME) or by malice.

*Mitigations in place (Phase 2, 3, 5)*:
- Scope rules are evaluated three times: plan, dispatch, ingestion.
- Every dropped target is recorded in the audit log with the rule that
  decided.
- The in-tree HTTP collector explicitly refuses to follow redirects,
  surfacing the redirect target as evidence instead.

*Gaps*:
- A collector that "discovers" a new target via target_discovered
  events is currently trusted to have scope-checked it; the supervisor
  re-checks at ingest, but a malicious collector could still cause an
  out-of-scope query to be made before the platform sees the event.
  The Phase 7 egress containment closes this gap.

### T4 — Audit log tampering

*Threat*: an actor with database write access edits or removes audit
events to cover their tracks.

*Mitigations in place (Phase 1)*:
- Every audit row carries `prev_hash` and `self_hash`; `self_hash` is
  HMAC-SHA256 of the canonical bytes under the audit signing key.
- `audit.Logger.Verify()` walks the chain and identifies the first
  broken row in O(n).
- The Phase-1 integration test demonstrates that flipping a single
  byte of metadata breaks `Verify`.

*Gaps*:
- The signing key currently lives in `audit.signing_key` in the YAML
  config. An attacker with both the database AND the config file can
  recompute valid hashes. A KMS-resident key (Phase 7+) closes this.

### T5 — Evidence tampering

*Threat*: an actor with DB or filesystem access modifies a finding's
description or replaces an artifact's bytes to mislead the report.

*Mitigations in place (Phase 4, 7)*:
- Artifacts are content-addressed; a byte change produces a different
  sha256 and a finding's evidence array references the old sha. The
  swap is detectable by re-hashing.
- Run manifests are HMAC-signed by the audit signing key and reference
  artifacts by sha256. Verifying the manifest catches any artifact or
  finding change after the manifest was issued.

*Gaps*:
- We do not sign artifacts individually; an unverified-manifest reader
  has to re-hash to detect tampering.
- Run manifests use the same key as the audit chain. Compromise of
  that key compromises both. Phase 7+ separates them.

### T6 — Denial of service from an authorized caller

*Threat*: a noisy operator (or runaway automation token) submits
thousands of runs and exhausts workers / database connections.

*Mitigations in place*:
- Worker pool is bounded.
- Per-collector / per-host rate caps are surfaced on rule matches as
  RateCaps; not yet enforced at dispatch.

*Gaps*:
- No global API rate limit. An automation token can submit
  POST /v1/runs at arbitrary frequency.
- No per-project quota on number of running jobs.

## Out of scope (intentionally)

- Multi-tenant SaaS isolation. PolyPent is single-tenant self-hosted in
  v1; tenant isolation is a question we revisit when there's a second
  tenant in the same daemon.
- LLM-driven triage. Not built, not threatened.
- Web UI security model. Begins with Phase 8.

## Decisions worth revisiting

1. **Bearer tokens vs mTLS for operator auth**: bearer is easier; mTLS
   gives request-binding and short-lived auto-rotation. Defer.
2. **One signing key vs two** (audit chain + manifest separately).
   Separation reduces blast radius. Likely to split in Phase 7.
3. **In-process worker pool vs separate worker daemon**. Splitting
   gives kernel-level isolation for collectors at the cost of two
   binaries to operate. Decide once one customer outgrows the
   single-process pool.
