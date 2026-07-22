# grype-verify

Offline-resilient OpenSSF SBOM vulnerability scanner that wraps [grype](https://github.com/anchore/grype) with automatic online/offline detection, persists every check result in an embedded SQLite database, and exposes a pull-based REST API for Splunk ingestion.

## How it works

On each `scan` invocation, `grype-verify` attempts `grype db update`. If that succeeds the scan runs with a fresh vulnerability database (online mode). If it fails — air-gapped lab, corporate proxy blocking the Anchore CDN, transient network issue — the scan continues using whatever database is cached locally and emits a staleness warning. Either way the result is stored and the exit code is propagated.

```
┌─────────────────────────────────────────┐
│  grype-verify scan <sbom>               │
│                                         │
│  grype db update ──► success: online    │
│                  └──► failure: offline  │
│                                         │
│  grype scan (GRYPE_DB_AUTO_UPDATE=false)│
│       │                                 │
│       ├─► stdout (table / sarif / json) │
│       └─► SQLite (grype-checks.db)      │
└─────────────────────────────────────────┘

  grype-verify serve ──► REST API ──► Splunk
```

## Prerequisites

**grype** is the only runtime dependency — `grype-verify` calls it as a subprocess.  
There is no public Rust library for grype (it is written in Go); invoking the binary is the only integration path.

| Tool | Required for | Install |
|------|-------------|---------|
| grype ≥ 0.88 | running scans | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh -s -- -b ~/bin` |
| Rust ≥ 1.84 | building grype-verify | system package or [rustup](https://rustup.rs) |

**syft** is _not_ a dependency of `grype-verify`.  
It is a separate tool used upstream to produce the SBOM files that `grype-verify scan` consumes.  
You can generate SBOMs with syft, GitHub's `anchore/sbom-action`, or any other OpenSSF-compatible tool.

## Build

```bash
git clone <repo-url> grype-verify
cd grype-verify
cargo build --release
# binary: target/release/grype-verify
```

## Quick start

```bash
# 1. Generate an SBOM for a repo
syft /path/to/upf --output spdx-json=upf.spdx.json

# 2. Scan and record the result
GRYPE_DB_CACHE_DIR=~/grype-db \
  grype-verify scan upf.spdx.json --output table --fail-on critical

# 3. Check status across all scanned SBOMs
grype-verify status
```

## Subcommand reference

### `scan`

```
grype-verify scan [OPTIONS] <SBOM_FILE>
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output` | `table` | grype output format: `table`, `json`, `sarif` |
| `--fail-on` | `medium` | Fail (exit 1) if vulnerabilities at or above this severity |
| `--only-fixed` | off | Only report vulnerabilities with a known fix |
| `--require-update` | off | Hard-fail if the DB update fails (CI release gate) |
| `--update-timeout` | 30 | Seconds to wait for `grype db update` |
| `--db-cache-dir` | `$GRYPE_DB_CACHE_DIR` | grype vulnerability DB cache path |
| `--checks-db` | `grype-checks.db` | SQLite result database path (`$GRYPE_CHECKS_DB`) |

**Exit codes** mirror grype: `0` = clean, `1` = vulnerabilities above threshold, `2` = tool error.

### `status`

```
grype-verify status [--json] [--checks-db PATH]
```

Prints a one-line summary of the latest scan per SBOM:

```
grype-verify: CLEAN | checks=12 | online | upf.spdx.json:clean(2026-07-09 16:10), amf.spdx.json:clean(2026-07-09 16:10)
```

Add `--json` for full structured output including raw grype results.

### `serve`

```
grype-verify serve [--port 8080] [--bind 127.0.0.1] [--checks-db PATH]
```

Starts a lightweight HTTP/1.1 REST API backed by the SQLite database. No external framework — uses only the Rust standard library.

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/health` | `{"status":"ok","checks_count":N}` |
| `GET /api/v1/checks` | All check records, newest first |
| `GET /api/v1/checks?since=<unix_ts>` | Records newer than this Unix timestamp (incremental pull) |
| `GET /api/v1/checks?limit=N` | Cap result count (default 100, max 10 000) |
| `GET /api/v1/checks/latest` | Most-recent check per distinct SBOM path |
| `?raw=1` on any endpoint | Include the raw grype output in the response |

Each record contains: `id`, `timestamp_iso`, `sbom_path`, `mode` (online/offline), `db_updated`, `exit_code`, `result` (clean/vulnerable/error), `fail_on`, `output_fmt`, `duration_ms`.

### Splunk integration

```
| rest url="http://host:8080/api/v1/checks?since=0&limit=500"
```

Splunk's `| rest` command automatically expands the `results` array into individual events. Use `since=<last_pulled_ts>` for incremental ingestion to avoid re-indexing.

> **Note:** If a corporate HTTP proxy is configured, ensure `no_proxy` or `NO_PROXY` includes the host running `grype-verify serve` so Splunk bypasses the proxy for the API call.

## Common recipes

```bash
# CI: fail the build if any critical CVE found and internet must be reachable
grype-verify scan app.spdx.json --fail-on critical --require-update

# Offline lab: scan with cached DB, warn but do not fail
GRYPE_DB_CACHE_DIR=/nfs/shared/grype-db grype-verify scan app.spdx.json

# Run the API on a shared host so the team can query it
GRYPE_CHECKS_DB=/nfs/shared/grype-checks.db \
  grype-verify serve --bind 0.0.0.0 --port 8080

# Fetch only records since a known timestamp
curl -s "http://host:8080/api/v1/checks?since=1783600000" | python3 -m json.tool
```

## Container image

A multi-stage `Dockerfile` is included. Build with:

```bash
podman build -t grype-verify:latest .

# Scan
podman run --rm \
  -v /path/to/grype-db:/data/grype-db \
  -v /path/to/checks:/data/checks \
  -v /path/to/sbom.spdx.json:/sbom.spdx.json:ro \
  grype-verify:latest scan /sbom.spdx.json --output table --fail-on critical

# API server
podman run -d --name grype-api \
  -v /path/to/checks:/data/checks \
  -p 8080:8080 \
  grype-verify:latest serve --bind 0.0.0.0 --port 8080
```

> **Rootless Podman note:** requires `/etc/subuid` and `/etc/subgid` entries for your user. Ask your sysadmin to run:
> ```
> echo "$(whoami):100000:65536" | sudo tee -a /etc/subuid /etc/subgid
> sudo podman system migrate
> ```

## Development

```bash
# Run all tests (19 unit tests, no network required)
cargo test

# Run a specific module
cargo test db::
cargo test serve::

# Check formatting and clippy
cargo fmt --check
cargo clippy -- -D warnings
```

### Embedded database schema

```sql
CREATE TABLE checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,   -- Unix seconds (UTC)
    sbom_path   TEXT    NOT NULL,
    mode        TEXT    NOT NULL,   -- 'online' | 'offline'
    db_updated  INTEGER NOT NULL,   -- 1 = DB was refreshed this run
    exit_code   INTEGER NOT NULL,   -- mirrors grype exit code
    fail_on     TEXT    NOT NULL,
    output_fmt  TEXT    NOT NULL,
    duration_ms INTEGER NOT NULL,
    raw_output  TEXT                -- grype stdout, capped at 512 KB
);
```

## Roadmap

- Vulnerability severity breakdown stored per scan (critical/high/medium counts) for trend dashboards
- Scheduled re-scan via systemd timer or cron
- SARIF output stored alongside table output for GitHub Code Scanning upload
- Shared grype DB cache across team via NFS mount — one online machine updates, the rest run offline
- Static musl binary build for fully self-contained deployment (no glibc dependency)

## License

Apache-2.0 — see [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)
