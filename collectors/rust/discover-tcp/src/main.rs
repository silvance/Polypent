// PolyPent reference Rust collector — bounded TCP-connect discovery.
//
// Reads one JobDescriptor on stdin, emits NDJSON on stdout per
// docs/collector-protocol.md.
//
// Target: kind=host, identity=<host>. Required parameter:
//   { "ports": "22,80,443,8000-8005" }
// Optional:
//   { "concurrency": 64, "connect_timeout_ms": 1500 }
//
// Rust's job here is what Rust is uniquely good at: bounded, predictable
// concurrency over thousands of small network I/O operations. No tokio
// dependency — std-lib threads with a bounded semaphore handle this
// fine and keep the build tiny.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const NAME: &str = "discover.tcp.syn";
const PROTOCOL_VERSION: &str = "polypent-ndjson/1";

fn emit(kind: &str, payload: Value) {
    let line = json!({"type": kind, "payload": payload}).to_string();
    println!("{}", line);
    // ensure flush; tests read with bufio.
    let _ = io::stdout().flush();
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut seen = BTreeSet::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Some(idx) = raw.find('-') {
            let (a, b) = raw.split_at(idx);
            let b = &b[1..];
            let lo: u32 = a.parse().map_err(|_| format!("bad range {raw}"))?;
            let hi: u32 = b.parse().map_err(|_| format!("bad range {raw}"))?;
            if lo < 1 || hi > 65535 || lo > hi {
                return Err(format!("bad range {raw}"));
            }
            for p in lo..=hi {
                seen.insert(p as u16);
            }
        } else {
            let p: u32 = raw.parse().map_err(|_| format!("bad port {raw}"))?;
            if p < 1 || p > 65535 {
                return Err(format!("bad port {raw}"));
            }
            seen.insert(p as u16);
        }
    }
    if seen.is_empty() {
        return Err("empty ports spec".into());
    }
    Ok(seen.into_iter().collect())
}

fn read_descriptor() -> Result<Value, String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("read stdin: {e}"))?;
    if line.is_empty() {
        return Err("no job descriptor on stdin".into());
    }
    serde_json::from_str(&line).map_err(|e| format!("parse descriptor: {e}"))
}

fn run() -> Result<i32, String> {
    let desc = read_descriptor()?;

    let target_kind = desc.get("target_kind").and_then(Value::as_str).unwrap_or("");
    if target_kind != "host" {
        return Err(format!("unsupported target_kind {target_kind:?}"));
    }
    let host = desc
        .get("target_identity")
        .and_then(Value::as_str)
        .ok_or("missing target_identity")?
        .to_string();
    if host.is_empty() {
        return Err("empty target".into());
    }
    let parameters = desc.get("parameters").cloned().unwrap_or(Value::Null);
    let ports_str = parameters
        .get("ports")
        .and_then(Value::as_str)
        .ok_or("parameters.ports required")?;
    let ports = parse_ports(ports_str)?;

    let concurrency = parameters
        .get("concurrency")
        .and_then(Value::as_u64)
        .unwrap_or(64)
        .max(1) as usize;
    let timeout_ms = parameters
        .get("connect_timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(1500);
    let timeout = Duration::from_millis(timeout_ms);

    let protocol = desc
        .get("protocol_version")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    emit(
        "hello",
        json!({
            "name": NAME,
            "version": "0.1.0",
            "protocol_version": protocol,
        }),
    );
    emit("ack", json!({"job_id": desc.get("job_id")}));
    emit(
        "log",
        json!({
            "level": "info",
            "message": format!(
                "scanning {} ports={} concurrency={} timeout_ms={}",
                host, ports.len(), concurrency, timeout_ms
            ),
        }),
    );

    let (tx_jobs, rx_jobs) = mpsc::channel::<u16>();
    for p in &ports {
        tx_jobs.send(*p).unwrap();
    }
    drop(tx_jobs);

    let rx_jobs = Arc::new(Mutex::new(rx_jobs));
    let open = Arc::new(Mutex::new(BTreeSet::<u16>::new()));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let rx = rx_jobs.clone();
        let open = open.clone();
        let host = host.clone();
        handles.push(thread::spawn(move || loop {
            let port = match rx.lock().unwrap().recv() {
                Ok(p) => p,
                Err(_) => break,
            };
            // Pre-resolve once per dial so a misbehaving DNS doesn't
            // amplify into N concurrent lookups.
            let addr: SocketAddr = match format!("{host}:{port}").to_socket_addrs() {
                Ok(mut it) => match it.next() {
                    Some(a) => a,
                    None => continue,
                },
                Err(_) => continue,
            };
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                open.lock().unwrap().insert(port);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let open_ports: Vec<u16> = open.lock().unwrap().iter().copied().collect();
    for &port in &open_ports {
        let target = format!("{host}:{port}");
        emit(
            "finding",
            json!({
                "kind": "port.open",
                "severity": "informational",
                "title": format!("TCP {target} open"),
                "dedup_key": format!("discover-tcp:open:{target}"),
                "extra": { "host": host, "port": port }
            }),
        );
    }

    emit(
        "done",
        json!({
            "host": host,
            "scanned": ports.len(),
            "open": open_ports.len(),
        }),
    );
    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("discover-tcp: {err}");
            emit(
                "error",
                json!({ "message": err, "fatal": true }),
            );
            std::process::exit(1);
        }
    }
}
