// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
//
// Integration tests — exercise the full scan → DB → API pipeline against real
// SBOM files.  Two env vars gate the test environment:
//
//   GRYPE_VERIFY_TEST_SBOM_DIR   path containing *.spdx.json files to scan
//                                (default: ../../  relative to the crate root,
//                                 which is verification/ in this repo layout)
//   GRYPE_DB_CACHE_DIR           grype DB cache dir (must be pre-populated;
//                                tests are skipped if not set)
//
// Run:
//   GRYPE_DB_CACHE_DIR=~/grype-db cargo test --test integration -- --nocapture

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

// ── helpers ───────────────────────────────────────────────────────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_db() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/grype-verify-itest-{}-{n}.db", std::process::id())
}

fn binary() -> PathBuf {
    // Works whether run via `cargo test` (target/debug) or directly.
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // strip test binary name
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("grype-verify")
}

fn sbom_dir() -> PathBuf {
    std::env::var("GRYPE_VERIFY_TEST_SBOM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Default: two levels up from the crate root → verification/
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .to_path_buf()
        })
}

/// Skip the test if the binary doesn't exist yet (not yet built in release mode).
fn require_binary() -> PathBuf {
    let bin = binary();
    if !bin.exists() {
        // Attempt to build it first so `cargo test --test integration` just works.
        let status = Command::new("cargo")
            .args(["build", "--release"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "cargo build --release failed");
        // After release build the binary is under target/release/, not target/debug/.
        let release = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/grype-verify");
        return release;
    }
    bin
}

/// Returns true when the grype DB cache dir env var is set and the dir exists.
fn db_cache_available() -> bool {
    std::env::var("GRYPE_DB_CACHE_DIR")
        .map(|d| Path::new(&d).exists())
        .unwrap_or(false)
}

fn find_sboms(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .filter(|p| p.to_str().map(|s| s.contains("spdx")).unwrap_or(false))
        .collect()
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Scan every *.spdx.json in GRYPE_VERIFY_TEST_SBOM_DIR, confirm each result
/// is recorded in the DB and the exit code is 0 or 1 (not a tool error).
#[test]
fn test_scan_real_sboms_and_record() {
    if !db_cache_available() {
        eprintln!("SKIP: GRYPE_DB_CACHE_DIR not set or does not exist");
        return;
    }

    let bin = require_binary();
    let sboms = find_sboms(&sbom_dir());
    assert!(
        !sboms.is_empty(),
        "no *.spdx.json files found in {:?}",
        sbom_dir()
    );

    let db_path = tmp_db();

    for sbom in &sboms {
        eprintln!("scanning {:?}", sbom);
        let out = Command::new(&bin)
            .args([
                "scan",
                sbom.to_str().unwrap(),
                "--output",
                "table",
                "--fail-on",
                "critical",
                "--update-timeout",
                "30",
                "--checks-db",
                &db_path,
            ])
            .env("GRYPE_DB_UPDATE_URL", "http://127.0.0.1:19999/offline") // force offline mode
            .output()
            .expect("failed to run grype-verify scan");

        // Print output for visibility with --nocapture
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&out.stdout));
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&out.stderr));

        // grype: 0 = clean, 2 = vulns at/above --fail-on, 1 = tool error
        let code = out.status.code().unwrap_or(99);
        assert!(
            code == 0 || code == 2,
            "unexpected exit code {code} for {:?} — expected 0 (clean) or 2 (vulnerable)",
            sbom
        );
    }

    // Verify all scans were recorded in the DB
    let status_out = Command::new(&bin)
        .args(["status", "--json", "--checks-db", &db_path])
        .output()
        .expect("failed to run grype-verify status");

    let json: serde_json::Value =
        serde_json::from_slice(&status_out.stdout).expect("status --json produced invalid JSON");

    let total = json["total_checks"].as_i64().unwrap_or(0);
    assert_eq!(
        total,
        sboms.len() as i64,
        "expected {n} recorded checks, got {total}",
        n = sboms.len()
    );

    std::fs::remove_file(&db_path).ok();
}

/// Scan one SBOM, start the API server, query /health and /checks/latest,
/// verify the response contains the expected record.
#[test]
fn test_api_returns_scan_result() {
    if !db_cache_available() {
        eprintln!("SKIP: GRYPE_DB_CACHE_DIR not set or does not exist");
        return;
    }

    let bin = require_binary();
    let sboms = find_sboms(&sbom_dir());
    assert!(
        !sboms.is_empty(),
        "no *.spdx.json files in {:?}",
        sbom_dir()
    );
    let sbom = &sboms[0];

    let db_path = tmp_db();

    // Run one scan
    let scan = Command::new(&bin)
        .args([
            "scan",
            sbom.to_str().unwrap(),
            "--output",
            "table",
            "--fail-on",
            "critical",
            "--update-timeout",
            "30",
            "--checks-db",
            &db_path,
        ])
        .env("GRYPE_DB_UPDATE_URL", "http://127.0.0.1:19999/offline")
        .output()
        .expect("scan failed");
    let code = scan.status.code().unwrap_or(99);
    assert!(code == 0 || code == 2, "scan exit code {code}");

    // Start API server on a random high port
    let port = 18080 + (std::process::id() % 1000);
    let mut server = Command::new(&bin)
        .args([
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--checks-db",
            &db_path,
        ])
        .spawn()
        .expect("failed to start serve");

    std::thread::sleep(std::time::Duration::from_millis(400));

    // Query health
    let health = Command::new("curl")
        .args([
            "-s",
            "--noproxy",
            "127.0.0.1",
            &format!("http://127.0.0.1:{port}/api/v1/health"),
        ])
        .output()
        .expect("curl health failed");
    let health_json: serde_json::Value =
        serde_json::from_slice(&health.stdout).expect("health response is not JSON");
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["checks_count"], 1);

    // Query /checks/latest
    let latest = Command::new("curl")
        .args([
            "-s",
            "--noproxy",
            "127.0.0.1",
            &format!("http://127.0.0.1:{port}/api/v1/checks/latest"),
        ])
        .output()
        .expect("curl latest failed");
    let latest_json: serde_json::Value =
        serde_json::from_slice(&latest.stdout).expect("latest response is not JSON");
    assert_eq!(latest_json["total"], 1);

    let result = &latest_json["results"][0];
    assert!(
        result["sbom_path"].as_str().unwrap().contains("spdx"),
        "sbom_path should contain 'spdx', got: {result}"
    );
    assert!(
        result["mode"] == "offline",
        "expected offline mode since we used a bad update URL"
    );

    server.kill().ok();
    server.wait().ok(); // reap the child so no zombie is left behind
    std::fs::remove_file(&db_path).ok();
}

/// Scan with --sarif-file and confirm a valid SARIF report is written alongside
/// the table output, and that its path is recorded in the database.
#[test]
fn test_sarif_written_alongside_table_output() {
    if !db_cache_available() {
        eprintln!("SKIP: GRYPE_DB_CACHE_DIR not set or does not exist");
        return;
    }

    let bin = require_binary();
    let sboms = find_sboms(&sbom_dir());
    assert!(
        !sboms.is_empty(),
        "no *.spdx.json files in {:?}",
        sbom_dir()
    );

    let db_path = tmp_db();
    let sarif_path = format!("/tmp/grype-verify-itest-{}.sarif", std::process::id());
    std::fs::remove_file(&sarif_path).ok();

    let out = Command::new(&bin)
        .args([
            "scan",
            sboms[0].to_str().unwrap(),
            "--output",
            "table",
            "--sarif-file",
            &sarif_path,
            "--fail-on",
            "critical",
            "--update-timeout",
            "5",
            "--checks-db",
            &db_path,
        ])
        .env("GRYPE_DB_UPDATE_URL", "http://127.0.0.1:19999/offline")
        .output()
        .expect("scan failed");

    let code = out.status.code().unwrap_or(99);
    assert!(code == 0 || code == 2, "scan exit code {code}");

    // stdout must still be the human-readable table, not SARIF.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\"$schema\""),
        "stdout should be table format, got SARIF"
    );

    // The SARIF file must exist and be a valid SARIF document.
    let sarif = std::fs::read_to_string(&sarif_path).expect("SARIF file was not written");
    let sarif_json: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF file is not valid JSON");
    assert!(
        sarif_json["runs"].is_array(),
        "SARIF document has no runs array"
    );

    // The recorded check must point at the SARIF file.
    let status_out = Command::new(&bin)
        .args(["status", "--json", "--checks-db", &db_path])
        .output()
        .expect("status failed");
    let json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(
        json["latest_per_sbom"][0]["sarif_path"],
        sarif_path.as_str()
    );

    std::fs::remove_file(&sarif_path).ok();
    std::fs::remove_file(&db_path).ok();
}

/// Confirm the severity breakdown recorded in the DB matches what grype itself
/// reports for the same SBOM, and that /api/v1/trend aggregates it.
#[test]
fn test_severity_breakdown_matches_grype_json() {
    if !db_cache_available() {
        eprintln!("SKIP: GRYPE_DB_CACHE_DIR not set or does not exist");
        return;
    }

    let bin = require_binary();
    let sboms = find_sboms(&sbom_dir());
    assert!(
        !sboms.is_empty(),
        "no *.spdx.json files in {:?}",
        sbom_dir()
    );
    let sbom = &sboms[0];

    let db_path = tmp_db();

    // Ground truth: ask grype directly for a JSON report and tally it here.
    let direct = Command::new("grype")
        .args(["--output", "json", &format!("sbom:{}", sbom.display())])
        .env("GRYPE_DB_AUTO_UPDATE", "false")
        .env("GRYPE_DB_VALIDATE_AGE", "false")
        .output()
        .expect("failed to run grype directly");
    let direct_json: serde_json::Value =
        serde_json::from_slice(&direct.stdout).expect("grype JSON output invalid");
    let expected_total = direct_json["matches"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    // Now the same scan through grype-verify.
    let out = Command::new(&bin)
        .args([
            "scan",
            sbom.to_str().unwrap(),
            "--output",
            "table",
            "--fail-on",
            "critical",
            "--update-timeout",
            "5",
            "--checks-db",
            &db_path,
        ])
        .env("GRYPE_DB_UPDATE_URL", "http://127.0.0.1:19999/offline")
        .output()
        .expect("scan failed");
    assert!(
        matches!(out.status.code(), Some(0) | Some(2)),
        "scan exit code {:?}",
        out.status.code()
    );

    let status_out = Command::new(&bin)
        .args(["status", "--json", "--checks-db", &db_path])
        .output()
        .expect("status failed");
    let json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    let rec = &json["latest_per_sbom"][0];

    assert_eq!(
        rec["total_vulns"].as_u64().unwrap_or(0) as usize,
        expected_total,
        "recorded total_vulns disagrees with grype's own match count"
    );

    // Severity fields must sum to the total.
    let sev = &rec["severity"];
    let sum: u64 = ["critical", "high", "medium", "low", "negligible", "unknown"]
        .iter()
        .map(|k| sev[*k].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(
        sum as usize, expected_total,
        "severity counts do not sum to total"
    );

    // The trend endpoint must surface the same numbers.
    let port = 18080 + (std::process::id() % 1000) + 1;
    let mut server = Command::new(&bin)
        .args([
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--checks-db",
            &db_path,
        ])
        .spawn()
        .expect("failed to start serve");
    std::thread::sleep(std::time::Duration::from_millis(400));

    let trend = Command::new("curl")
        .args([
            "-s",
            "--noproxy",
            "127.0.0.1",
            &format!("http://127.0.0.1:{port}/api/v1/trend?days=7"),
        ])
        .output()
        .expect("curl trend failed");
    server.kill().ok();
    server.wait().ok(); // reap the child so no zombie is left behind

    let trend_json: serde_json::Value =
        serde_json::from_slice(&trend.stdout).expect("trend response is not JSON");
    assert_eq!(trend_json["total"], 1, "expected one day bucket");
    assert_eq!(
        trend_json["results"][0]["total_vulns"]
            .as_u64()
            .unwrap_or(0) as usize,
        expected_total
    );

    std::fs::remove_file(&db_path).ok();
}

/// Verify that --require-update causes a non-zero exit when the DB update URL
/// is unreachable (offline simulation).
#[test]
fn test_require_update_fails_offline() {
    let bin = require_binary();
    let sboms = find_sboms(&sbom_dir());
    if sboms.is_empty() {
        eprintln!("SKIP: no SBOM files found");
        return;
    }

    let db_path = tmp_db();
    let out = Command::new(&bin)
        .args([
            "scan",
            sboms[0].to_str().unwrap(),
            "--require-update",
            "--update-timeout",
            "2",
            "--checks-db",
            &db_path,
        ])
        .env("GRYPE_DB_UPDATE_URL", "http://127.0.0.1:19999/offline")
        .output()
        .expect("failed to run grype-verify");

    let code = out.status.code().unwrap_or(0);
    assert_ne!(
        code, 0,
        "--require-update should fail when DB update is unreachable"
    );

    std::fs::remove_file(&db_path).ok();
}
