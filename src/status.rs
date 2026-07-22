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
    let conn = db::open(&args.checks_db)
        .with_context(|| format!("cannot open {}", args.checks_db))?;

    let total = db::count(&conn)?;
    let latest = db::query_latest_per_sbom(&conn)?;

    if args.json {
        let obj = serde_json::json!({
            "total_checks": total,
            "latest_per_sbom": latest,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    // ── one-liner summary ──────────────────────────────────────────────
    if total == 0 {
        println!("grype-verify: no checks recorded yet (db={})", args.checks_db);
        return Ok(());
    }

    // Overall pass/fail across the latest check for every SBOM
    let any_vuln = latest.iter().any(|r| r.exit_code == 1);
    let any_error = latest.iter().any(|r| r.exit_code > 1);
    let any_offline = latest.iter().any(|r| r.mode == "offline");

    let status_flag = if any_error {
        "ERROR"
    } else if any_vuln {
        "VULNERABLE"
    } else {
        "CLEAN"
    };

    let sbom_summary: Vec<String> = latest
        .iter()
        .map(|r| {
            // Use just the filename part of the path for brevity
            let name = std::path::Path::new(&r.sbom_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&r.sbom_path);
            format!(
                "{}:{}({})",
                name,
                r.result,
                r.timestamp_iso.as_deref().unwrap_or("?")
            )
        })
        .collect();

    println!(
        "grype-verify: {status_flag} | checks={total} | db={db} | {mode} | {sboms}",
        status_flag = status_flag,
        total = total,
        db = args.checks_db,
        mode = if any_offline { "offline" } else { "online" },
        sboms = sbom_summary.join(", "),
    );

    Ok(())
}
