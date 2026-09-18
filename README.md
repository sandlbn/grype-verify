# grype-verify

Offline-resilient OpenSSF SBOM vulnerability scanner that wraps [grype](https://github.com/anchore/grype) with automatic online/offline detection, persists every check result in an embedded SQLite database, and exposes a pull-based REST API for Splunk ingestion.

## How it works

On each `scan` invocation, `grype-verify` attempts `grype db update`. If that succeeds the scan runs with a fresh vulnerability database (online mode). If it fails — air-gapped lab, corporate proxy blocking the Anchore CDN, transient network issue — the scan continues using whatever database is cached locally and emits a staleness warning. Either way the result is stored and the exit code is propagated.

```
┌──────────────────────────────────────────────────┐
│  grype-verify scan <sbom>                        │
│                                                  │
│  grype db update ──► success: online             │
│                  └──► failure: offline (warn)    │
│                                                  │
│  grype scan (GRYPE_DB_AUTO_UPDATE=false)         │
│       │                                          │
│       ├─► stdout      table / json / sarif       │
│       ├─► SARIF file  --sarif-file (optional)    │
│       ├─► JSON report parsed → severity counts   │
│       └─► SQLite      grype-checks.db            │
└──────────────────────────────────────────────────┘

  systemd timer / cron ──► periodic re-scan
  grype-verify serve   ──► REST API ──► Splunk
```

A single grype invocation feeds all of these — grype's `-o` accepts repeated
`format=file` targets, so the severity breakdown and SARIF report cost no extra scan.

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
| `--fail-on` | `medium` | Fail if vulnerabilities at or above this severity are found |
| `--sarif-file` | — | Also write a SARIF report to this path, independent of `--output` |
| `--only-fixed` | off | Only report vulnerabilities with a known fix |
| `--require-update` | off | Hard-fail if the DB update fails (CI release gate) |
| `--update-timeout` | 30 | Seconds to wait for `grype db update` |
| `--db-cache-dir` | `$GRYPE_DB_CACHE_DIR` | grype vulnerability DB cache path |
| `--checks-db` | `grype-checks.db` | SQLite result database path (`$GRYPE_CHECKS_DB`) |

**Exit codes** mirror grype exactly:

| Code | Meaning |
|------|---------|
| `0` | Clean — no vulnerabilities at or above `--fail-on` |
| `1` | Tool error — missing SBOM, unreadable DB, bad flag |
| `2` | Vulnerabilities found at or above `--fail-on` |

> Note the ordering: grype returns **2** for findings and **1** for errors, which is the
> opposite of the more common convention. Scripts that branch on the exit code should
> treat `2` as "scan succeeded, vulnerabilities present".

### Severity breakdown

Every scan records a per-severity tally alongside the result. `grype-verify` always asks
grype for a JSON report on the side — regardless of the format you chose for stdout — and
parses `matches[].vulnerability.severity` from it. One scan, no extra grype invocation:

```
[grype-verify] Severity breakdown: critical=0 high=15 medium=8 low=0 negligible=0 unknown=0 (total=23)
```

These counts are stored per scan, so the API can serve trend data without re-parsing
anything.

### SARIF alongside a readable format

`--sarif-file` is independent of `--output`, so CI can show a human-readable table in the
job log *and* upload SARIF to GitHub Code Scanning from the same scan:

```bash
grype-verify scan app.spdx.json --output table --sarif-file results.sarif
```

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The SARIF path is recorded in the database so the API can point consumers at the report.

### `status`

```
grype-verify status [--json] [--checks-db PATH]
```

Prints a one-line summary of the latest scan per SBOM, with aggregate severity counts
and a per-SBOM `[C… H… M…]` breakdown:

```
grype-verify: VULNERABLE | checks=12 | db=grype-checks.db | online | vulns=23 (C0 H15 M8 L0 N0 U0) | upf.spdx.json:vulnerable[C0 H15 M8](2026-09-18 01:08)
```

Add `--json` for full structured output including `severity_totals` and raw grype results.

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
| `GET /api/v1/trend?days=N` | Severity counts bucketed by UTC day (default 30, max 3650) |
| `?raw=1` on any endpoint | Include the raw grype output in the response |

Each record contains: `id`, `timestamp_iso`, `sbom_path`, `mode` (online/offline), `db_updated`, `exit_code`, `result` (clean/vulnerable/error), `fail_on`, `output_fmt`, `duration_ms`, `total_vulns`, `sarif_path`, and a nested `severity` object:

```json
{
  "sbom_path": "upf.spdx.json",
  "result": "vulnerable",
  "mode": "online",
  "total_vulns": 23,
  "severity": {
    "critical": 0, "high": 15, "medium": 8,
    "low": 0, "negligible": 0, "unknown": 0
  },
  "sarif_path": "/var/lib/grype-verify/sarif/upf.sarif"
}
```

`/api/v1/trend` returns one row per day, summed across all scans that day — ready to plot
without client-side bucketing:

```json
{"total": 2, "results": [
  {"day": "2026-09-18", "scans": 2, "total_vulns": 34,
   "severity": {"critical": 0, "high": 23, "medium": 9, "low": 0, "negligible": 0, "unknown": 2}}
]}
```

### Splunk integration

```
| rest url="http://host:8080/api/v1/checks?since=0&limit=500"
```

Splunk's `| rest` command automatically expands the `results` array into individual events. Use `since=<last_pulled_ts>` for incremental ingestion to avoid re-indexing.

Severity fields arrive as `severity.critical`, `severity.high`, … so trend dashboards are
a single search:

```
| rest url="http://host:8080/api/v1/checks?since=0&limit=1000"
| timechart span=1d sum(severity.critical) AS Critical, sum(severity.high) AS High
```

Or let the API do the bucketing and just chart what it returns:

```
| rest url="http://host:8080/api/v1/trend?days=90"
| eval _time=strptime(day,"%Y-%m-%d")
| timechart span=1d sum(severity.critical) AS Critical, sum(severity.high) AS High
```

Components currently scanning against a stale DB (offline mode):

```
| rest url="http://host:8080/api/v1/checks/latest"
| search mode=offline
| table sbom_path timestamp_iso result total_vulns
```

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

# CI: readable table in the job log, SARIF uploaded to Code Scanning
grype-verify scan app.spdx.json --output table --sarif-file results.sarif --fail-on high

# 90-day severity trend, pre-bucketed by day
curl -s "http://host:8080/api/v1/trend?days=90" | python3 -m json.tool

# Re-scan a whole directory of SBOMs (what the systemd timer runs)
SBOM_DIR=/var/lib/grype-verify/sboms SARIF_DIR=/tmp/sarif ./deploy/scan-all.sh
```

## Scheduled re-scans

New CVEs are published against unchanged dependencies every day, so the value of a
periodic re-scan comes from re-scanning the *same* SBOM — no rebuild needed. The
`deploy/` directory contains everything for a systemd or cron schedule:

| File | Purpose |
|------|---------|
| `deploy/scan-all.sh` | Scans every `*.spdx.json` in `$SBOM_DIR`, recording each result |
| `deploy/grype-verify-scan.service` | Oneshot unit that runs the above |
| `deploy/grype-verify-scan.timer` | Daily at 03:00, with a 30 min random spread |
| `deploy/grype-verify-api.service` | Long-running REST API for Splunk to poll |
| `deploy/grype-verify.env` | Shared config for both units |
| `deploy/crontab.example` | cron equivalent for hosts without systemd |

### systemd

```bash
sudo useradd --system --home /var/lib/grype-verify grype-verify
sudo install -m 0755 deploy/scan-all.sh /usr/local/bin/grype-verify-scan-all
sudo install -m 0644 deploy/grype-verify.env /etc/grype-verify.env
sudo cp deploy/grype-verify-{scan.service,scan.timer,api.service} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now grype-verify-scan.timer grype-verify-api

# Check the schedule and run one now without waiting
systemctl list-timers grype-verify-scan.timer
sudo systemctl start grype-verify-scan.service
journalctl -u grype-verify-scan.service -n 50
```

Drop the SBOMs to watch into `$SBOM_DIR` (default `/var/lib/grype-verify/sboms`). Whatever
produces them — syft, a CI artifact download, an rsync job — is out of scope for this tool.

Two details worth knowing:

- The unit sets `SuccessExitStatus=0 2` so a vulnerable result is recorded as a successful
  scan rather than a failed unit. Only a genuine tool error (exit 1) marks the timer failed.
- `scan-all.sh` never aborts early: one vulnerable component does not stop the remaining
  SBOMs from being scanned and recorded. It exits with the worst outcome seen.

### cron

```bash
sudo install -m 0755 deploy/scan-all.sh /usr/local/bin/grype-verify-scan-all
crontab -e   # then paste from deploy/crontab.example
```

cron runs with a minimal environment, so `deploy/crontab.example` sets `PATH` explicitly —
otherwise neither `grype` nor `grype-verify` will be found.

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

# Scan and keep the SARIF report
podman run --rm \
  -v /path/to/grype-db:/data/grype-db \
  -v /path/to/checks:/data/checks \
  -v /path/to/sarif:/data/sarif \
  -v /path/to/sbom.spdx.json:/sbom.spdx.json:ro \
  grype-verify:latest scan /sbom.spdx.json \
    --output table --sarif-file /data/sarif/app.sarif --fail-on high

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
# Unit tests — 31 tests, no network or grype binary required
cargo test --bin grype-verify

# Integration tests — need grype on PATH and a populated DB cache.
# Skipped automatically when GRYPE_DB_CACHE_DIR is unset.
GRYPE_DB_CACHE_DIR=~/grype-db \
GRYPE_VERIFY_TEST_SBOM_DIR=/path/to/sboms \
  cargo test --test integration -- --nocapture

# Run a specific module
cargo test db::
cargo test serve::

# Exactly what CI enforces
cargo fmt --check
cargo clippy --all-targets -- -D warnings
shellcheck deploy/*.sh
```

### Embedded database schema

```sql
CREATE TABLE checks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      INTEGER NOT NULL,   -- Unix seconds (UTC)
    sbom_path      TEXT    NOT NULL,
    mode           TEXT    NOT NULL,   -- 'online' | 'offline'
    db_updated     INTEGER NOT NULL,   -- 1 = DB was refreshed this run
    exit_code      INTEGER NOT NULL,   -- mirrors grype exit code
    fail_on        TEXT    NOT NULL,
    output_fmt     TEXT    NOT NULL,
    duration_ms    INTEGER NOT NULL,
    sev_critical   INTEGER NOT NULL DEFAULT 0,
    sev_high       INTEGER NOT NULL DEFAULT 0,
    sev_medium     INTEGER NOT NULL DEFAULT 0,
    sev_low        INTEGER NOT NULL DEFAULT 0,
    sev_negligible INTEGER NOT NULL DEFAULT 0,
    sev_unknown    INTEGER NOT NULL DEFAULT 0,
    sarif_path     TEXT,               -- set when --sarif-file was used
    raw_output     TEXT                -- grype stdout, capped at 512 KB
);
```

Databases created by v0.2.0 are migrated in place on first open — the severity and SARIF
columns are added via `ALTER TABLE` and existing rows read back with zeroed counts. No
manual migration step, and no data loss.

## Roadmap

- Shared grype DB cache across team via NFS mount — one online machine updates, the rest run offline
- Static musl binary build for fully self-contained deployment (no glibc dependency)
- Per-CVE detail rows (not just counts) so the API can answer "which components are affected by CVE-X"
- Retention policy / pruning for the checks database on long-running collectors

## License

Apache-2.0 — see [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)
