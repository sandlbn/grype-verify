// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
//
// Minimal HTTP/1.1 server — no external framework, only std + serde_json + rusqlite.
//
// Endpoints (all return application/json):
//
//   GET /api/v1/health
//       {"status":"ok","checks_count":<n>}
//
//   GET /api/v1/checks[?since=<unix_ts>&limit=<n>&raw=1]
//       {"total":<n>,"results":[...]}
//       since  – only return checks with timestamp > value (unix seconds)
//       limit  – cap result count (default 100, max 10 000)
//       raw    – include raw_output field when set to 1 (omitted by default)
//
//   GET /api/v1/checks/latest[?raw=1]
//       Most-recent check per SBOM path.
//       {"total":<n>,"results":[...]}
//
// Splunk usage:
//   | rest url="http://<host>:8080/api/v1/checks?since=0&limit=500"
//   | rest url="http://<host>:8080/api/v1/checks/latest"

use anyhow::Context;
use clap::Args;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::db;

#[derive(Args)]
pub struct ServeArgs {
    /// Path to the SQLite checks database
    #[arg(long, env = "GRYPE_CHECKS_DB", default_value = "grype-checks.db")]
    pub checks_db: String,

    /// TCP port to listen on
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Address to bind
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
}

// ─── request parsing ─────────────────────────────────────────────────────────

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
}

fn parse_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).ok()?;

    let mut parts = first_line.split_whitespace();
    let method = parts.next()?.to_string();
    let raw_path = parts.next()?;

    let (path, query_str) = match raw_path.find('?') {
        Some(idx) => (&raw_path[..idx], &raw_path[idx + 1..]),
        None => (raw_path, ""),
    };

    let query: Vec<(String, String)> = query_str
        .split('&')
        .filter(|s| s.contains('='))
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (k, v)
        })
        .collect();

    Some(Request {
        method,
        path: path.to_string(),
        query,
    })
}

fn qparam<'a>(query: &'a [(String, String)], key: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

// ─── HTTP response helpers ────────────────────────────────────────────────────

fn http_ok(body: String) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    )
}

fn http_err(status: &str, msg: &str) -> String {
    let body = format!("{{\"error\":\"{msg}\"}}");
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    )
}

// ─── route handlers ───────────────────────────────────────────────────────────

fn handle_health(db_path: &str) -> String {
    match db::open(db_path).and_then(|c| db::count(&c)) {
        Ok(n) => http_ok(format!("{{\"status\":\"ok\",\"checks_count\":{n}}}")),
        Err(e) => http_err("500 Internal Server Error", &e.to_string()),
    }
}

fn handle_checks(db_path: &str, query: &[(String, String)]) -> String {
    let since: Option<i64> = qparam(query, "since").and_then(|v| v.parse().ok());
    let limit: Option<i64> = qparam(query, "limit").and_then(|v| v.parse().ok());
    let include_raw = qparam(query, "raw").map(|v| v == "1").unwrap_or(false);

    match db::open(db_path).and_then(|c| db::query_checks(&c, since, limit)) {
        Ok(mut records) => {
            if !include_raw {
                for r in &mut records {
                    r.raw_output = None;
                }
            }
            match serde_json::to_string(&records) {
                Ok(arr) => http_ok(format!("{{\"total\":{},\"results\":{arr}}}", records.len())),
                Err(e) => http_err("500 Internal Server Error", &e.to_string()),
            }
        }
        Err(e) => http_err("500 Internal Server Error", &e.to_string()),
    }
}

fn handle_latest(db_path: &str, query: &[(String, String)]) -> String {
    let include_raw = qparam(query, "raw").map(|v| v == "1").unwrap_or(false);

    match db::open(db_path).and_then(|c| db::query_latest_per_sbom(&c)) {
        Ok(mut records) => {
            if !include_raw {
                for r in &mut records {
                    r.raw_output = None;
                }
            }
            match serde_json::to_string(&records) {
                Ok(arr) => http_ok(format!("{{\"total\":{},\"results\":{arr}}}", records.len())),
                Err(e) => http_err("500 Internal Server Error", &e.to_string()),
            }
        }
        Err(e) => http_err("500 Internal Server Error", &e.to_string()),
    }
}

fn handle_trend(db_path: &str, query: &[(String, String)]) -> String {
    let days: Option<i64> = qparam(query, "days").and_then(|v| v.parse().ok());

    match db::open(db_path).and_then(|c| db::query_trend(&c, days)) {
        Ok(points) => match serde_json::to_string(&points) {
            Ok(arr) => http_ok(format!("{{\"total\":{},\"results\":{arr}}}", points.len())),
            Err(e) => http_err("500 Internal Server Error", &e.to_string()),
        },
        Err(e) => http_err("500 Internal Server Error", &e.to_string()),
    }
}

// ─── connection handler ───────────────────────────────────────────────────────

fn handle_connection(mut stream: TcpStream, db_path: &str) -> anyhow::Result<()> {
    let req = match parse_request(&stream) {
        Some(r) => r,
        None => {
            stream.write_all(http_err("400 Bad Request", "malformed request").as_bytes())?;
            return Ok(());
        }
    };

    if req.method != "GET" {
        stream.write_all(http_err("405 Method Not Allowed", "only GET supported").as_bytes())?;
        return Ok(());
    }

    let response = match req.path.as_str() {
        "/api/v1/health" => handle_health(db_path),
        "/api/v1/checks/latest" => handle_latest(db_path, &req.query),
        "/api/v1/checks" => handle_checks(db_path, &req.query),
        "/api/v1/trend" => handle_trend(db_path, &req.query),
        _ => http_err("404 Not Found", "unknown endpoint"),
    };

    stream
        .write_all(response.as_bytes())
        .context("failed to write HTTP response")?;
    Ok(())
}

// ─── server entry point ───────────────────────────────────────────────────────

pub fn run(args: ServeArgs) -> anyhow::Result<()> {
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = TcpListener::bind(&addr).with_context(|| format!("failed to bind to {addr}"))?;

    eprintln!("[grype-verify] API server listening on http://{addr}");
    eprintln!("[grype-verify] Endpoints:");
    eprintln!("  GET http://{addr}/api/v1/health");
    eprintln!("  GET http://{addr}/api/v1/checks[?since=<unix_ts>&limit=<n>&raw=1]");
    eprintln!("  GET http://{addr}/api/v1/checks/latest[?raw=1]");
    eprintln!("  GET http://{addr}/api/v1/trend[?days=<n>]");
    eprintln!("[grype-verify] Splunk: | rest url=\"http://{addr}/api/v1/checks\"");

    // Ensure the DB and schema exist before accepting connections.
    db::open(&args.checks_db).context("failed to open checks DB")?;

    let db_path = Arc::new(args.checks_db);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let db_path = Arc::clone(&db_path);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(s, &db_path) {
                        eprintln!("[grype-verify] handler error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[grype-verify] accept error: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    // Build a minimal HTTP/1.1 request string the same way curl does.
    fn make_request(method: &str, path: &str) -> String {
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    // Write a fake HTTP request into one end of a local socket and parse from the other.
    fn parse(raw: &str) -> Option<Request> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let raw = raw.to_string();
        std::thread::spawn(move || {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(raw.as_bytes()).unwrap();
        });
        let (server_side, _) = listener.accept().unwrap();
        parse_request(&server_side)
    }

    #[test]
    fn test_parse_simple_get() {
        let req = parse(&make_request("GET", "/api/v1/health")).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/v1/health");
        assert!(req.query.is_empty());
    }

    #[test]
    fn test_parse_path_with_query() {
        let req = parse(&make_request("GET", "/api/v1/checks?since=1000&limit=50")).unwrap();
        assert_eq!(req.path, "/api/v1/checks");
        assert_eq!(qparam(&req.query, "since"), Some("1000"));
        assert_eq!(qparam(&req.query, "limit"), Some("50"));
    }

    #[test]
    fn test_parse_raw_flag() {
        let req = parse(&make_request("GET", "/api/v1/checks?raw=1")).unwrap();
        assert_eq!(qparam(&req.query, "raw"), Some("1"));
    }

    #[test]
    fn test_qparam_missing_key() {
        let query = vec![("since".to_string(), "100".to_string())];
        assert_eq!(qparam(&query, "limit"), None);
    }

    #[test]
    fn test_http_ok_has_correct_content_length() {
        let body = r#"{"status":"ok"}"#.to_string();
        let response = http_ok(body.clone());
        let expected = format!("Content-Length: {}", body.len());
        assert!(response.contains(&expected));
        assert!(response.ends_with(&body));
    }

    #[test]
    fn test_http_ok_content_type() {
        let response = http_ok("{}".to_string());
        assert!(response.contains("Content-Type: application/json"));
    }

    #[test]
    fn test_http_err_contains_message() {
        let response = http_err("404 Not Found", "unknown endpoint");
        assert!(response.contains("404 Not Found"));
        assert!(response.contains("unknown endpoint"));
    }

    // Return a unique file path in /tmp per test (cleaned up after use).
    // Using thread-id + a counter avoids collisions when tests run in parallel.
    fn tmp_db() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/grype-verify-test-{}-{n}.db", std::process::id())
    }

    #[test]
    fn test_handle_health_with_empty_db() {
        let path = tmp_db();
        crate::db::open(&path).unwrap();
        let resp = handle_health(&path);
        std::fs::remove_file(&path).ok();
        assert!(resp.contains("\"status\":\"ok\""));
        assert!(resp.contains("\"checks_count\":0"));
    }

    #[test]
    fn test_handle_checks_empty() {
        let path = tmp_db();
        crate::db::open(&path).unwrap();
        let resp = handle_checks(&path, &[]);
        std::fs::remove_file(&path).ok();
        assert!(resp.contains("\"total\":0"));
        assert!(resp.contains("\"results\":[]"));
    }

    #[test]
    fn test_handle_latest_with_data() {
        let path = tmp_db();
        let conn = crate::db::open(&path).unwrap();
        let rec = crate::db::CheckRecord {
            id: 0,
            timestamp: 9999,
            timestamp_iso: None,
            sbom_path: "test.spdx.json".to_string(),
            mode: "online".to_string(),
            db_updated: true,
            exit_code: 0,
            result: "clean".to_string(),
            fail_on: "critical".to_string(),
            output_fmt: "table".to_string(),
            duration_ms: 100,
            severity: crate::db::SeverityCounts {
                critical: 1,
                high: 2,
                ..Default::default()
            },
            total_vulns: 3,
            sarif_path: None,
            raw_output: None,
        };
        crate::db::insert(&conn, &rec).unwrap();
        drop(conn);
        let resp = handle_latest(&path, &[]);
        std::fs::remove_file(&path).ok();
        assert!(resp.contains("\"total\":1"));
        assert!(resp.contains("test.spdx.json"));
    }

    #[test]
    fn test_handle_latest_includes_severity_breakdown() {
        let path = tmp_db();
        let conn = crate::db::open(&path).unwrap();
        let rec = crate::db::CheckRecord {
            id: 0,
            timestamp: 9999,
            timestamp_iso: None,
            sbom_path: "test.spdx.json".to_string(),
            mode: "online".to_string(),
            db_updated: true,
            exit_code: 2,
            result: "vulnerable".to_string(),
            fail_on: "critical".to_string(),
            output_fmt: "table".to_string(),
            duration_ms: 100,
            severity: crate::db::SeverityCounts {
                critical: 4,
                high: 7,
                ..Default::default()
            },
            total_vulns: 11,
            sarif_path: Some("/tmp/x.sarif".to_string()),
            raw_output: None,
        };
        crate::db::insert(&conn, &rec).unwrap();
        drop(conn);
        let resp = handle_latest(&path, &[]);
        std::fs::remove_file(&path).ok();
        assert!(resp.contains("\"critical\":4"), "resp: {resp}");
        assert!(resp.contains("\"high\":7"));
        assert!(resp.contains("\"total_vulns\":11"));
        assert!(resp.contains("/tmp/x.sarif"));
    }

    #[test]
    fn test_handle_trend_aggregates_by_day() {
        let path = tmp_db();
        let conn = crate::db::open(&path).unwrap();
        for (ts, crit) in [(86_400, 1), (86_500, 2), (200_000, 5)] {
            let mut rec = crate::db::CheckRecord {
                id: 0,
                timestamp: ts,
                timestamp_iso: None,
                sbom_path: "a.spdx.json".to_string(),
                mode: "online".to_string(),
                db_updated: true,
                exit_code: 0,
                result: "clean".to_string(),
                fail_on: "critical".to_string(),
                output_fmt: "table".to_string(),
                duration_ms: 10,
                severity: crate::db::SeverityCounts::default(),
                total_vulns: 0,
                sarif_path: None,
                raw_output: None,
            };
            rec.severity.critical = crit;
            rec.total_vulns = rec.severity.total();
            crate::db::insert(&conn, &rec).unwrap();
        }
        drop(conn);
        let resp = handle_trend(&path, &[]);
        std::fs::remove_file(&path).ok();
        // Two distinct days: 1970-01-02 (1+2 critical) and 1970-01-03 (5 critical)
        assert!(resp.contains("\"total\":2"), "resp: {resp}");
        assert!(resp.contains("1970-01-02"));
        assert!(resp.contains("1970-01-03"));
    }
}
