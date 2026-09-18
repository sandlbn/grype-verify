// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
use anyhow::Context;
use clap::Args;

use crate::db;

#[derive(Args)]
pub struct StatusArgs {
    /// Path to the SQLite checks database
    #[arg(long, env = "GRYPE_CHECKS_DB", default_value = "grype-checks.db")]
    pub checks_db: String,

    /// Show full JSON instead of the one-line summary
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: StatusArgs) -> anyhow::Result<()> {
    let conn =
        db::open(&args.checks_db).with_context(|| format!("cannot open {}", args.checks_db))?;

    let total = db::count(&conn)?;
    let latest = db::query_latest_per_sbom(&conn)?;

    if args.json {
        let mut totals = db::SeverityCounts::default();
        for r in &latest {
            totals.critical += r.severity.critical;
            totals.high += r.severity.high;
            totals.medium += r.severity.medium;
            totals.low += r.severity.low;
            totals.negligible += r.severity.negligible;
            totals.unknown += r.severity.unknown;
        }
        let obj = serde_json::json!({
            "total_checks": total,
            "severity_totals": totals,
            "total_vulns": totals.total(),
            "latest_per_sbom": latest,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    // ── one-liner summary ──────────────────────────────────────────────
    if total == 0 {
        println!(
            "grype-verify: no checks recorded yet (db={})",
            args.checks_db
        );
        return Ok(());
    }

    // Overall pass/fail across the latest check for every SBOM
    let any_vuln = latest.iter().any(|r| r.result == "vulnerable");
    let any_error = latest.iter().any(|r| r.result == "error");
    let any_offline = latest.iter().any(|r| r.mode == "offline");

    let status_flag = if any_error {
        "ERROR"
    } else if any_vuln {
        "VULNERABLE"
    } else {
        "CLEAN"
    };

    // Aggregate severity counts across the latest check of every SBOM.
    let mut totals = db::SeverityCounts::default();
    for r in &latest {
        totals.critical += r.severity.critical;
        totals.high += r.severity.high;
        totals.medium += r.severity.medium;
        totals.low += r.severity.low;
        totals.negligible += r.severity.negligible;
        totals.unknown += r.severity.unknown;
    }

    let sbom_summary: Vec<String> = latest
        .iter()
        .map(|r| {
            // Use just the filename part of the path for brevity
            let name = std::path::Path::new(&r.sbom_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&r.sbom_path);
            format!(
                "{}:{}[C{} H{} M{}]({})",
                name,
                r.result,
                r.severity.critical,
                r.severity.high,
                r.severity.medium,
                r.timestamp_iso.as_deref().unwrap_or("?")
            )
        })
        .collect();

    println!(
        "grype-verify: {status_flag} | checks={total} | db={db} | {mode} | \
         vulns={vulns} (C{c} H{h} M{m} L{l} N{n} U{u}) | {sboms}",
        status_flag = status_flag,
        total = total,
        db = args.checks_db,
        mode = if any_offline { "offline" } else { "online" },
        vulns = totals.total(),
        c = totals.critical,
        h = totals.high,
        m = totals.medium,
        l = totals.low,
        n = totals.negligible,
        u = totals.unknown,
        sboms = sbom_summary.join(", "),
    );

    Ok(())
}
