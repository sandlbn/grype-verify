// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
use anyhow::Context;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Max bytes of grype stdout to persist; avoids unbounded DB growth on large SBOMs.
const MAX_OUTPUT_BYTES: usize = 512 * 1024;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn result_label(exit_code: i32) -> &'static str {
    match exit_code {
        0 => "clean",
        1 => "vulnerable",
        _ => "error",
    }
}

pub fn open(path: &str) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open checks DB at {path}"))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS checks (
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
         CREATE INDEX IF NOT EXISTS idx_ts   ON checks(timestamp);
         CREATE INDEX IF NOT EXISTS idx_sbom ON checks(sbom_path);",
    )
    .context("failed to initialise checks DB schema")?;
    Ok(conn)
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
             fail_on, output_fmt, duration_ms, raw_output)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            rec.timestamp,
            rec.sbom_path,
            rec.mode,
            rec.db_updated as i32,
            rec.exit_code,
            rec.fail_on,
            rec.output_fmt,
            rec.duration_ms,
            truncated,
        ],
    )
    .context("failed to insert check record")?;
    Ok(conn.last_insert_rowid())
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<CheckRecord> {
    let exit_code: i32 = row.get(4)?;
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
        raw_output: row.get(10)?,
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
    let cap = limit.unwrap_or(100).max(1).min(10_000);
    let since = since_ts.unwrap_or(0);
    let mut stmt = conn.prepare(
        "SELECT id,
                timestamp,
                datetime(timestamp,'unixepoch') AS timestamp_iso,
                sbom_path, exit_code, mode, db_updated,
                fail_on, output_fmt, duration_ms, raw_output
         FROM checks
         WHERE timestamp > ?1
         ORDER BY timestamp DESC
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![since, cap], row_to_record)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query checks")?;
    Ok(rows)
}

/// Most recent check for each distinct sbom_path.
pub fn query_latest_per_sbom(conn: &Connection) -> anyhow::Result<Vec<CheckRecord>> {
    let mut stmt = conn.prepare(
        "SELECT c.id,
                c.timestamp,
                datetime(c.timestamp,'unixepoch') AS timestamp_iso,
                c.sbom_path, c.exit_code, c.mode, c.db_updated,
                c.fail_on, c.output_fmt, c.duration_ms, c.raw_output
         FROM checks c
         INNER JOIN (
             SELECT sbom_path, MAX(timestamp) AS max_ts
             FROM checks
             GROUP BY sbom_path
         ) m ON c.sbom_path = m.sbom_path AND c.timestamp = m.max_ts
         ORDER BY c.timestamp DESC",
    )?;
    let rows = stmt
        .query_map([], row_to_record)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("failed to query latest checks")?;
    Ok(rows)
}

pub fn count(conn: &Connection) -> anyhow::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM checks", [], |r| r.get(0))
        .context("failed to count checks")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS checks (
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
             CREATE INDEX IF NOT EXISTS idx_ts   ON checks(timestamp);
             CREATE INDEX IF NOT EXISTS idx_sbom ON checks(sbom_path);",
        )
        .unwrap();
        conn
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

        let a = latest.iter().find(|r| r.sbom_path == "a.spdx.json").unwrap();
        assert_eq!(a.timestamp, 3000, "should return the newest check for a.spdx.json");

        let b = latest.iter().find(|r| r.sbom_path == "b.spdx.json").unwrap();
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
    fn test_result_label() {
        assert_eq!(result_label(0), "clean");
        assert_eq!(result_label(1), "vulnerable");
        assert_eq!(result_label(2), "error");
        assert_eq!(result_label(99), "error");
    }
}
