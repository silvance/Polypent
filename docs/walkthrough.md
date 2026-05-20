# First engagement walkthrough

This is the Phase 5 exit-criterion walkthrough: standing up a project,
defining scope, running the in-tree Go collectors against a sample
target, and listing the findings — end to end, via the CLI.

It assumes:

- `polypentd` and `polypent` built (`go build ./cmd/...`)
- A reachable Postgres
- A YAML config at `./polypent.yaml`:

```yaml
server:
  addr: 127.0.0.1:8080
database:
  url: postgres://polypent:devpw@127.0.0.1:5432/polypent_dev?sslmode=disable
audit:
  signing_key: dev-key-32-bytes-aaaaaaaaaaaaaaaa
log:
  level: info
  format: text
queue:
  workers: 4
storage:
  artifacts_dir: ./var/polypent/artifacts
```

## 1. Migrate and start the daemon

```sh
./polypentd migrate --config ./polypent.yaml
./polypentd serve   --config ./polypent.yaml
```

The first start mints a single-use admin token and logs it once. Capture
it:

```
level=INFO msg="BOOTSTRAP TOKEN ISSUED" token=pp_admin_xxxxxxxxxxxxxxx
```

```sh
export POLYPENT_API_URL=http://127.0.0.1:8080
export POLYPENT_API_TOKEN=pp_admin_xxxxxxxxxxxxxxx
```

## 2. Create a project

```sh
polypent project create --slug acme-2026 --name "Acme Q2 Engagement" --owner alice@example.com
```

Note the returned `id`; export it for convenience:

```sh
export PROJECT=<paste-uuid>
```

## 3. Define scope

```sh
polypent scope add  --project $PROJECT --order 0 --effect allow --kind cidr --value 10.0.0.0/8
polypent scope add  --project $PROJECT --order 1 --effect allow --kind dns_suffix --value example.com
polypent scope list --project $PROJECT
```

A scope check is a safe dry-run that you can use before kicking a real
run:

```sh
polypent scope check --project $PROJECT --kind host --identity 10.0.0.5 --host 10.0.0.5
# {"effect":"allow", ...}

polypent scope check --project $PROJECT --kind host --identity 8.8.8.8 --host 8.8.8.8
# {"effect":"out_of_scope", ...}
```

## 4. Run the built-in Go collectors

The four Phase 5 in-tree collectors are registered at boot:

| name              | target kind | example identity            |
|-------------------|-------------|-----------------------------|
| `http.probe`      | url / host  | `https://10.0.0.5/`         |
| `dns.passive`     | dns_name    | `app.example.com`           |
| `tls.inspect`     | host        | `10.0.0.5:443`              |
| `port.tcp.connect`| host        | `10.0.0.5` + params.ports   |

A single run can specify multiple capabilities and targets. The planner
scope-clamps and produces one job per `(capability, target)` pair:

```sh
polypent run create \
  --project $PROJECT \
  --capabilities http.probe,tls.inspect \
  --targets 'host=10.0.0.5,host=10.0.0.5:443' \
  --deadline-seconds 60
# {"id":"<run-uuid>","kept_targets":4,"dropped_targets":0}

export RUN=<run-uuid>
```

A `port.tcp.connect` run takes a port spec via `--params`:

```sh
polypent run create \
  --project $PROJECT \
  --capabilities port.tcp.connect \
  --targets 'host=10.0.0.5' \
  --params '{"ports":"22,80,443,8000-8005","concurrency":8}'
```

## 5. Watch progress

```sh
polypent run status --run $RUN
```

The job listing shows `queued → leased → running → succeeded`. The
worker pool picks jobs up automatically; nothing else needs to be done.

## 6. List findings

```sh
polypent finding list --project $PROJECT
polypent finding list --project $PROJECT --severity medium
polypent finding list --project $PROJECT --kind info.http.live
```

Re-running the same collectors against the same target does **not**
create duplicate findings; each collector uses a deterministic
`dedup_key` per target+kind, so `last_seen_at` advances and evidence
accumulates instead.

## 7. Pull evidence

Each finding lists its `evidence` as a set of sha256s. Download by
hash:

```sh
curl -H "Authorization: Bearer $POLYPENT_API_TOKEN" \
     $POLYPENT_API_URL/v1/artifacts/<sha256> -o response.http
```

## 8. Register an external collector (optional)

Drop a collector following the NDJSON protocol (see
`docs/collector-protocol.md` and the reference implementations under
`collectors/`), make it executable, and register it:

```sh
curl -X POST -H "Authorization: Bearer $POLYPENT_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"echo","language":"python","version":"0.1.0",
          "binary_path":"/abs/path/to/collectors/python/echo/main.py",
          "transport":"ndjson"}' \
     $POLYPENT_API_URL/v1/collectors
```

It is now dispatchable as `--capabilities echo` in subsequent
`polypent run create` calls.

The repository ships four reference external collectors that all pass
the protocol conformance suite (`internal/conformance`):

| binary                                                          | language | what it does                         |
|-----------------------------------------------------------------|----------|--------------------------------------|
| `collectors/python/echo/main.py`                                | python   | scripted lifecycle for tests / smoke |
| `collectors/python/smb_enum/main.py`                            | python   | SMB negotiate (live with impacket)   |
| `collectors/python/ldap_enum/main.py`                           | python   | anonymous-bind discovery (ldap3)     |
| `collectors/rust/target/release/discover-tcp`                   | rust     | bounded high-throughput TCP scan     |

The Python collectors degrade to a structural "dry run" emission when
their optional dependencies (impacket, ldap3) are not installed, so the
protocol conformance suite passes on any host.

Build the Rust collector once with:

```sh
cargo build --release --manifest-path collectors/rust/Cargo.toml
```
