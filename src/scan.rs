// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
use anyhow::Context;
use clap::Args;
use std::process::Command;
use std::time::Instant;

use crate::db;

#[derive(Args)]
pub struct ScanArgs {
    /// Path to the SPDX JSON SBOM to scan
    pub sbom_file: String,

    /// Grype DB cache directory
    #[arg(long, env = "GRYPE_DB_CACHE_DIR")]
    pub db_cache_dir: Option<String>,

    /// Output format: table, json, sarif
    #[arg(long, default_value = "table")]
    pub output: String,

    /// Fail on vulnerabilities at or above this severity
    #[arg(long, default_value = "medium")]
    pub fail_on: String,

    /// Only report vulnerabilities with a known fix
    #[arg(long)]
    pub only_fixed: bool,

    /// Fail if the DB update fails (instead of falling back to cached DB)
    #[arg(long)]
    pub require_update: bool,

    /// DB update timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub update_timeout: u64,

    /// Path to the SQLite checks database (set to empty string to skip recording)
    #[arg(long, env = "GRYPE_CHECKS_DB", default_value = "grype-checks.db")]
    pub checks_db: String,
}

fn grype_env(db_cache_dir: &Option<String>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(dir) = db_cache_dir {
        env.push(("GRYPE_DB_CACHE_DIR".to_string(), dir.clone()));
    }
    env
}

/// Attempt `grype db update`. Returns true if the update succeeded.
fn try_db_update(args: &ScanArgs) -> anyhow::Result<bool> {
    let status = Command::new("grype")
        .args(["db", "update"])
        .envs(grype_env(&args.db_cache_dir))
        .env(
            "GRYPE_DB_UPDATE_TIMEOUT",
            format!("{}s", args.update_timeout),
        )
        .status()
        .context("failed to spawn `grype db update` — is grype on PATH?")?;
    Ok(status.success())
}

/// Run grype scan, capturing stdout for DB storage while re-emitting to our stdout.
fn run_grype_scan(args: &ScanArgs, skip_auto_update: bool) -> anyhow::Result<(i32, String)> {
    let mut cmd = Command::new("grype");
    cmd.args(["--output", &args.output, "--fail-on", &args.fail_on]);
    if args.only_fixed {
        cmd.arg("--only-fixed");
    }
    cmd.arg(format!("sbom:{}", args.sbom_file));
    cmd.envs(grype_env(&args.db_cache_dir));

    if skip_auto_update {
        cmd.env("GRYPE_DB_AUTO_UPDATE", "false");
        cmd.env("GRYPE_DB_VALIDATE_AGE", "false");
    }

    // Capture stdout for storage; inherit stderr so grype's warnings appear live.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    let output = cmd.output().context("failed to run grype scan")?;
    let stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();

    // Re-emit captured stdout so the caller sees the scan results.
    print!("{}", stdout_text);

    let code = output.status.code().unwrap_or(2);
    Ok((code, stdout_text))
}

pub fn run(args: ScanArgs) -> anyhow::Result<()> {
    eprintln!("[grype-verify] Attempting vulnerability database update...");
    let db_updated = try_db_update(&args)?;

    let mode = if db_updated {
        eprintln!("[grype-verify] Database updated successfully (online mode).");
        "online"
    } else if args.require_update {
        anyhow::bail!(
            "DB update failed and --require-update is set. \
             Ensure network connectivity to grype.anchore.io."
        );
    } else {
        eprintln!(
            "[grype-verify] WARNING: DB update failed — using cached database. \
             Results may reflect stale vulnerability data."
        );
        "offline"
    };

    let t0 = Instant::now();
    let (exit_code, raw_output) = run_grype_scan(&args, true)?;
    let duration_ms = t0.elapsed().as_millis() as i64;

    // Record the result unless the user opted out with an empty path.
    if !args.checks_db.is_empty() {
        let conn = db::open(&args.checks_db)?;
        let rec = db::CheckRecord {
            id: 0, // assigned by DB
            timestamp: db::now_unix(),
            timestamp_iso: None,
            sbom_path: args.sbom_file.clone(),
            mode: mode.to_string(),
            db_updated,
            exit_code,
            result: db::result_label(exit_code).to_string(),
            fail_on: args.fail_on.clone(),
            output_fmt: args.output.clone(),
            duration_ms,
            raw_output: Some(raw_output),
        };
        let row_id = db::insert(&conn, &rec)?;
        eprintln!(
            "[grype-verify] Result recorded (check id={row_id}, db={}).",
            args.checks_db
        );
    }

    std::process::exit(exit_code);
}
