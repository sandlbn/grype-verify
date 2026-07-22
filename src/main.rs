// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Intel Corporation
mod db;
mod scan;
mod serve;
mod status;

use clap::{Parser, Subcommand};

/// Offline-aware grype vulnerability scanner with embedded result tracking and REST API.
///
/// Examples:
///   grype-verify scan upf.spdx.json --output table --fail-on critical
///   grype-verify status
///   grype-verify serve --port 8080
#[derive(Parser)]
#[command(version, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a vulnerability scan and record the result to the embedded database.
    Scan(scan::ScanArgs),
    /// Print a one-line status summary of the latest check per SBOM (--json for full detail).
    Status(status::StatusArgs),
    /// Start the REST API server so Splunk (or any HTTP client) can pull check history.
    Serve(serve::ServeArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => scan::run(args),
        Commands::Status(args) => status::run(args),
        Commands::Serve(args) => serve::run(args),
    }
}
