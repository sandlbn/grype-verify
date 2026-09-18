// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
use anyhow::Context;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Max bytes of grype stdout to persist; avoids unbounded DB growth on large SBOMs.
const MAX_OUTPUT_BYTES: usize = 512 * 1024;

/// Per-scan vulnerability counts broken down by grype severity level.
/// Stored as individual columns so Splunk can chart trends without parsing raw output.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub negligible: i64,
    pub unknown: i64,
}

impl SeverityCounts {
    pub fn total(&self) -> i64 {
        self.critical + self.high + self.medium + self.low + self.negligible + self.unknown
    }

    /// Tally grype JSON report output (the `matches[].vulnerability.severity` field).
    /// Unrecognised or absent severities fall into `unknown`.
    pub fn from_grype_json(json: &str) -> anyhow::Result<Self> {
        let parsed: serde_json::Value =
            serde_json::from_str(json).context("grype JSON report is not valid JSON")?;
        let matches = parsed
            .get("matches")
            .and_then(|m| m.as_array())
            .context("grype JSON report has no `matches` array")?;

        let mut counts = SeverityCounts::default();
        for m in matches {
            let sev = m
                .get("vulnerability")
                .and_then(|v| v.get("severity"))
                .and_then(|s| s.as_str())
                .unwrap_or("Unknown");
            match sev.to_ascii_lowercase().as_str() {
                "critical" => counts.critical += 1,
                "high" => counts.high += 1,
                "medium" => counts.medium += 1,
                "low" => counts.low += 1,
                "negligible" => counts.negligible += 1,
                _ => counts.unknown += 1,
            }
        }
        Ok(counts)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRecord {
    pub id: i64,
    /// Unix timestamp (seconds since epoch) — query layer formats as ISO 8601 via SQLite.
    pub timestamp: i64,
    /// ISO 8601 string derived by SQLite datetime(); present in query results only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_iso: Option<String>,
    pub sbom_path: String,
    /// "online" or "offline"
    pub mode: String,
    pub db_updated: bool,
    pub exit_code: i32,
    /// Human-readable result: "clean", "vulnerable", or "error"
    pub result: String,
    pub fail_on: String,
    pub output_fmt: String,
    pub duration_ms: i64,
    /// Vulnerability counts per severity level.
    pub severity: SeverityCounts,
    /// Sum of all severity counts — convenience field for dashboards.
    pub total_vulns: i64,
    /// Path to the SARIF report written for this scan, when --sarif-file was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sarif_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map a grype exit code to a human-readable result.
///
/// grype's contract (verified against v0.115):
///   0 — no vulnerabilities at or above --fail-on
///   1 — application error (bad flag, missing SBOM, unreadable DB)
///   2 — vulnerabilities found at or above --fail-on
pub fn result_label(exit_code: i32) -> &'static str {
    match exit_code {
        0 => "clean",
        2 => "vulnerable",
        _ => "error",
    }
}

/// Columns added after v0.2.0. Databases created by an older version are
/// migrated in place when opened.
const ADDED_COLUMNS: &[(&str, &str)] = &[
    ("sev_critical", "INTEGER NOT NULL DEFAULT 0"),
    ("sev_high", "INTEGER NOT NULL DEFAULT 0"),
    ("sev_medium", "INTEGER NOT NULL DEFAULT 0"),
    ("sev_low", "INTEGER NOT NULL DEFAULT 0"),
    ("sev_negligible", "INTEGER NOT NULL DEFAULT 0"),
    ("sev_unknown", "INTEGER NOT NULL DEFAULT 0"),
    ("sarif_path", "TEXT"),
];

pub fn open(path: &str) -> anyhow::Result<Connection> {
    let conn =
        Connection::open(path).with_context(|| format!("failed to open checks DB at {path}"))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS checks (
             id             INTEGER PRIMARY KEY AUTOINCREMENT,
             timestamp      INTEGER NOT NULL,
             sbom_path      TEXT    NOT NULL,
             mode           TEXT    NOT NULL,
             db_updated     INTEGER NOT NULL,
             exit_code      INTEGER NOT NULL,
             fail_on        TEXT    NOT NULL,
             output_fmt     TEXT    NOT NULL,
             duration_ms    INTEGER NOT NULL,
             sev_critical   INTEGER NOT NULL DEFAULT 0,
             sev_high       INTEGER NOT NULL DEFAULT 0,
             sev_medium     INTEGER NOT NULL DEFAULT 0,
             sev_low        INTEGER NOT NULL DEFAULT 0,
             sev_negligible INTEGER NOT NULL DEFAULT 0,
             sev_unknown    INTEGER NOT NULL DEFAULT 0,
             sarif_path     TEXT,
             raw_output     TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_ts   ON checks(timestamp);
         CREATE INDEX IF NOT EXISTS idx_sbom ON checks(sbom_path);",
    )
    .context("failed to initialise checks DB schema")?;
    migrate(&conn)?;
    Ok(conn)
}

/// Add any columns missing from a database created by an older version.
/// SQLite has no `ADD COLUMN IF NOT EXISTS`, so diff against table_info first.
fn migrate(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(checks)")?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to read checks table schema")?;

    for (name, decl) in ADDED_COLUMNS {
        if !existing.iter().any(|c| c == name) {
            conn.execute_batch(&format!("ALTER TABLE checks ADD COLUMN {name} {decl};"))
                .with_context(|| format!("failed to add column {name} to checks table"))?;
        }
    }
    Ok(())
}

pub fn insert(conn: &Connection, rec: &CheckRecord) -> anyhow::Result<i64> {
    let truncated = rec.raw_output.as_deref().map(|s| {
        if s.len() > MAX_OUTPUT_BYTES {
            &s[..MAX_OUTPUT_BYTES]
        } else {
            s
        }
    });
    conn.execute(
        "INSERT INTO checks
            (timestamp, sbom_path, mode, db_updated, exit_code,
             fail_on, output_fmt, duration_ms,
             sev_critical, sev_high, sev_medium, sev_low, sev_negligible, sev_unknown,
             sarif_path, raw_output)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
            rec.timestamp,
            rec.sbom_path,
            rec.mode,
            rec.db_updated as i32,
            rec.exit_code,
            rec.fail_on,
            rec.output_fmt,
            rec.duration_ms,
            rec.severity.critical,
            rec.severity.high,
            rec.severity.medium,
            rec.severity.low,
            rec.severity.negligible,
            rec.severity.unknown,
            rec.sarif_path,
            truncated,
        ],
    )
    .context("failed to insert check record")?;
    Ok(conn.last_insert_rowid())
}

/// Shared SELECT list so both queries stay index-aligned with `row_to_record`.
/// Qualified with `c.` — every query must alias the checks table as `c`.
const SELECT_COLUMNS: &str = "c.id,
     c.timestamp,
     datetime(c.timestamp,'unixepoch') AS timestamp_iso,
     c.sbom_path, c.exit_code, c.mode, c.db_updated,
     c.fail_on, c.output_fmt, c.duration_ms,
     c.sev_critical, c.sev_high, c.sev_medium,
     c.sev_low, c.sev_negligible, c.sev_unknown,
     c.sarif_path, c.raw_output";

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<CheckRecord> {
    let exit_code: i32 = row.get(4)?;
    let severity = SeverityCounts {
        critical: row.get(10)?,
        high: row.get(11)?,
        medium: row.get(12)?,
        low: row.get(13)?,
        negligible: row.get(14)?,
        unknown: row.get(15)?,
    };
    Ok(CheckRecord {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        timestamp_iso: row.get(2)?,
        sbom_path: row.get(3)?,
        mode: row.get(5)?,
        db_updated: row.get::<_, i32>(6)? != 0,
        exit_code,
        result: result_label(exit_code).to_string(),
        fail_on: row.get(7)?,
        output_fmt: row.get(8)?,
        duration_ms: row.get(9)?,
        total_vulns: severity.total(),
        severity,
        sarif_path: row.get(16)?,
        raw_output: row.get(17)?,
    })
}

/// Return checks ordered newest-first.
/// `since_ts` filters to rows with timestamp > value (unix secs).
/// `limit` caps the result set (default 100).
pub fn query_checks(
    conn: &Connection,
    since_ts: Option<i64>,
    limit: Option<i64>,
) -> anyhow::Result<Vec<CheckRecord>> {
    let cap = limit.unwrap_or(100).clamp(1, 10_000);
    let since = since_ts.unwrap_or(0);
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS}
         FROM checks c
         WHERE c.timestamp > ?1
         ORDER BY c.timestamp DESC
         LIMIT ?2"
    ))?;
    let rows = stmt
        .query_map(params![since, cap], row_to_record)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query checks")?;
    Ok(rows)
}

/// Most recent check for each distinct sbom_path.
pub fn query_latest_per_sbom(conn: &Connection) -> anyhow::Result<Vec<CheckRecord>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS}
         FROM checks c
         INNER JOIN (
             SELECT sbom_path, MAX(timestamp) AS max_ts
             FROM checks
             GROUP BY sbom_path
         ) m ON c.sbom_path = m.sbom_path AND c.timestamp = m.max_ts
         ORDER BY c.timestamp DESC"
    ))?;
    let rows = stmt
        .query_map([], row_to_record)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query latest checks")?;
    Ok(rows)
}

/// One row per calendar day (UTC), summing severity counts across all scans that
/// day. Feeds time-series dashboards without the client having to bucket itself.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrendPoint {
    /// UTC date, `YYYY-MM-DD`.
    pub day: String,
    pub scans: i64,
    pub severity: SeverityCounts,
    pub total_vulns: i64,
}

pub fn query_trend(conn: &Connection, days: Option<i64>) -> anyhow::Result<Vec<TrendPoint>> {
    let cap = days.unwrap_or(30).clamp(1, 3650);
    let mut stmt = conn.prepare(
        "SELECT date(timestamp,'unixepoch') AS day,
                COUNT(*),
                SUM(sev_critical), SUM(sev_high), SUM(sev_medium),
                SUM(sev_low), SUM(sev_negligible), SUM(sev_unknown)
         FROM checks
         GROUP BY day
         ORDER BY day DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![cap], |row| {
            let severity = SeverityCounts {
                critical: row.get(2)?,
                high: row.get(3)?,
                medium: row.get(4)?,
                low: row.get(5)?,
                negligible: row.get(6)?,
                unknown: row.get(7)?,
            };
            Ok(TrendPoint {
                day: row.get(0)?,
                scans: row.get(1)?,
                total_vulns: severity.total(),
                severity,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query severity trend")?;
    Ok(rows)
}

pub fn count(conn: &Connection) -> anyhow::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM checks", [], |r| r.get(0))
        .context("failed to count checks")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory DB built through `open()` so tests exercise the real schema
    /// (including the migration path) rather than a hand-copied duplicate.
    fn temp_conn() -> Connection {
        open(":memory:").unwrap()
    }

    fn sample_record(sbom: &str, mode: &str, exit_code: i32, ts: i64) -> CheckRecord {
        CheckRecord {
            id: 0,
            timestamp: ts,
            timestamp_iso: None,
            sbom_path: sbom.to_string(),
            mode: mode.to_string(),
            db_updated: mode == "online",
            exit_code,
            result: result_label(exit_code).to_string(),
            fail_on: "critical".to_string(),
            output_fmt: "table".to_string(),
            duration_ms: 500,
            severity: SeverityCounts::default(),
            total_vulns: 0,
            sarif_path: None,
            raw_output: Some("No vulnerabilities found".to_string()),
        }
    }

    #[test]
    fn test_open_creates_schema() {
        let conn = open(":memory:").unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM checks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_insert_and_count() {
        let conn = temp_conn();
        assert_eq!(count(&conn).unwrap(), 0);
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        insert(&conn, &sample_record("b.spdx.json", "offline", 0, 2000)).unwrap();
        assert_eq!(count(&conn).unwrap(), 2);
    }

    #[test]
    fn test_insert_returns_incrementing_ids() {
        let conn = temp_conn();
        let id1 = insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        let id2 = insert(&conn, &sample_record("b.spdx.json", "online", 0, 2000)).unwrap();
        assert!(id2 > id1);
    }

    #[test]
    fn test_query_checks_newest_first() {
        let conn = temp_conn();
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        insert(&conn, &sample_record("b.spdx.json", "online", 0, 3000)).unwrap();
        insert(&conn, &sample_record("c.spdx.json", "offline", 1, 2000)).unwrap();

        let rows = query_checks(&conn, None, None).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].timestamp, 3000);
        assert_eq!(rows[1].timestamp, 2000);
        assert_eq!(rows[2].timestamp, 1000);
    }

    #[test]
    fn test_query_checks_since_filter() {
        let conn = temp_conn();
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        insert(&conn, &sample_record("b.spdx.json", "online", 0, 2000)).unwrap();
        insert(&conn, &sample_record("c.spdx.json", "online", 0, 3000)).unwrap();

        let rows = query_checks(&conn, Some(1500), None).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.timestamp > 1500));
    }

    #[test]
    fn test_query_checks_limit() {
        let conn = temp_conn();
        for ts in 1..=10 {
            insert(&conn, &sample_record("a.spdx.json", "online", 0, ts)).unwrap();
        }
        let rows = query_checks(&conn, None, Some(3)).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn test_query_latest_per_sbom_returns_newest() {
        let conn = temp_conn();
        // Three checks for a.spdx.json — timestamps 1000, 2000, 3000
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 3000)).unwrap();
        insert(&conn, &sample_record("a.spdx.json", "offline", 0, 2000)).unwrap();
        // One check for b.spdx.json
        insert(&conn, &sample_record("b.spdx.json", "online", 1, 1500)).unwrap();

        let latest = query_latest_per_sbom(&conn).unwrap();
        assert_eq!(latest.len(), 2);

        let a = latest
            .iter()
            .find(|r| r.sbom_path == "a.spdx.json")
            .unwrap();
        assert_eq!(
            a.timestamp, 3000,
            "should return the newest check for a.spdx.json"
        );

        let b = latest
            .iter()
            .find(|r| r.sbom_path == "b.spdx.json")
            .unwrap();
        assert_eq!(b.exit_code, 1);
    }

    #[test]
    fn test_raw_output_truncated_at_limit() {
        let conn = temp_conn();
        let mut rec = sample_record("a.spdx.json", "online", 0, 1000);
        rec.raw_output = Some("x".repeat(MAX_OUTPUT_BYTES + 100));
        insert(&conn, &rec).unwrap();

        let rows = query_checks(&conn, None, None).unwrap();
        let stored = rows[0].raw_output.as_deref().unwrap_or("");
        assert!(stored.len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn test_result_label_matches_grype_exit_codes() {
        // grype: 0 = clean, 1 = application error, 2 = vulns at/above --fail-on
        assert_eq!(result_label(0), "clean");
        assert_eq!(result_label(1), "error");
        assert_eq!(result_label(2), "vulnerable");
        assert_eq!(result_label(99), "error");
    }

    // ── severity breakdown ────────────────────────────────────────────────

    fn grype_json(severities: &[&str]) -> String {
        let matches: Vec<serde_json::Value> = severities
            .iter()
            .map(|s| serde_json::json!({"vulnerability": {"severity": s}}))
            .collect();
        serde_json::json!({ "matches": matches }).to_string()
    }

    #[test]
    fn test_severity_counts_from_grype_json() {
        let json = grype_json(&["Critical", "High", "High", "Medium", "Low", "Negligible"]);
        let c = SeverityCounts::from_grype_json(&json).unwrap();
        assert_eq!(c.critical, 1);
        assert_eq!(c.high, 2);
        assert_eq!(c.medium, 1);
        assert_eq!(c.low, 1);
        assert_eq!(c.negligible, 1);
        assert_eq!(c.unknown, 0);
        assert_eq!(c.total(), 6);
    }

    #[test]
    fn test_severity_counts_case_insensitive() {
        let c = SeverityCounts::from_grype_json(&grype_json(&["CRITICAL", "critical"])).unwrap();
        assert_eq!(c.critical, 2);
    }

    #[test]
    fn test_severity_counts_unrecognised_goes_to_unknown() {
        let c = SeverityCounts::from_grype_json(&grype_json(&["Unknown", "bogus"])).unwrap();
        assert_eq!(c.unknown, 2);
        assert_eq!(c.total(), 2);
    }

    #[test]
    fn test_severity_counts_empty_matches() {
        let c = SeverityCounts::from_grype_json(&grype_json(&[])).unwrap();
        assert_eq!(c, SeverityCounts::default());
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn test_severity_counts_missing_severity_field() {
        let json = r#"{"matches":[{"vulnerability":{"id":"CVE-1"}}]}"#;
        let c = SeverityCounts::from_grype_json(json).unwrap();
        assert_eq!(c.unknown, 1);
    }

    #[test]
    fn test_severity_counts_rejects_non_grype_json() {
        assert!(SeverityCounts::from_grype_json("not json").is_err());
        assert!(SeverityCounts::from_grype_json(r#"{"no_matches":[]}"#).is_err());
    }

    #[test]
    fn test_severity_counts_round_trip_through_db() {
        let conn = temp_conn();
        let mut rec = sample_record("a.spdx.json", "online", 2, 1000);
        rec.severity = SeverityCounts {
            critical: 3,
            high: 5,
            medium: 2,
            low: 1,
            negligible: 0,
            unknown: 4,
        };
        rec.total_vulns = rec.severity.total();
        rec.sarif_path = Some("/tmp/out.sarif".to_string());
        insert(&conn, &rec).unwrap();

        let rows = query_checks(&conn, None, None).unwrap();
        assert_eq!(rows[0].severity, rec.severity);
        assert_eq!(rows[0].total_vulns, 15);
        assert_eq!(rows[0].sarif_path.as_deref(), Some("/tmp/out.sarif"));
        assert_eq!(rows[0].result, "vulnerable");
    }

    #[test]
    fn test_latest_per_sbom_carries_severity() {
        let conn = temp_conn();
        let mut old = sample_record("a.spdx.json", "online", 0, 1000);
        old.severity.high = 9;
        insert(&conn, &old).unwrap();

        let mut new = sample_record("a.spdx.json", "online", 0, 2000);
        new.severity.high = 1;
        insert(&conn, &new).unwrap();

        let latest = query_latest_per_sbom(&conn).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].severity.high, 1, "should carry the newest counts");
    }

    // ── schema migration ──────────────────────────────────────────────────

    #[test]
    fn test_migrate_adds_columns_to_legacy_schema() {
        let conn = Connection::open_in_memory().unwrap();
        // Recreate the pre-0.3.0 schema, which lacks severity and sarif columns.
        conn.execute_batch(
            "CREATE TABLE checks (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp   INTEGER NOT NULL,
                 sbom_path   TEXT    NOT NULL,
                 mode        TEXT    NOT NULL,
                 db_updated  INTEGER NOT NULL,
                 exit_code   INTEGER NOT NULL,
                 fail_on     TEXT    NOT NULL,
                 output_fmt  TEXT    NOT NULL,
                 duration_ms INTEGER NOT NULL,
                 raw_output  TEXT
             );
             INSERT INTO checks
                (timestamp, sbom_path, mode, db_updated, exit_code,
                 fail_on, output_fmt, duration_ms, raw_output)
             VALUES (1000,'legacy.spdx.json','online',1,0,'critical','table',10,'old');",
        )
        .unwrap();

        migrate(&conn).unwrap();

        // The pre-existing row survives and reads back with zeroed counts.
        let rows = query_checks(&conn, None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sbom_path, "legacy.spdx.json");
        assert_eq!(rows[0].severity, SeverityCounts::default());
        assert_eq!(rows[0].sarif_path, None);
        assert_eq!(rows[0].raw_output.as_deref(), Some("old"));
    }

    #[test]
    fn test_migrate_is_idempotent() {
        let conn = temp_conn();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        insert(&conn, &sample_record("a.spdx.json", "online", 0, 1000)).unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
    }
}
