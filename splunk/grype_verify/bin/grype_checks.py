#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation
#
# Splunk scripted input: pull scan results from the grype-verify REST API.
#
# Splunk's `| rest` search command can only reach Splunk's own management API,
# so an external JSON API has to be ingested by an input rather than a search.
# This script is that input: Splunk runs it on an interval, it fetches everything
# recorded since the last run, and prints one JSON object per line to stdout.
#
# Incremental state is a single file holding the newest timestamp already sent,
# so restarts and interval changes never re-index the same check twice.
#
# Configuration (inputs.conf or environment):
#   GRYPE_VERIFY_URL    base URL of the API   (default http://127.0.0.1:8080)
#   GRYPE_VERIFY_STATE  state file path       (default $SPLUNK_HOME/var/lib/splunk/modinputs/grype_verify/last_ts)
#   GRYPE_VERIFY_LIMIT  max records per poll  (default 1000)

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_LIMIT = 1000


def state_path() -> str:
    explicit = os.environ.get("GRYPE_VERIFY_STATE")
    if explicit:
        return explicit
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return os.path.join(
        splunk_home, "var", "lib", "splunk", "modinputs", "grype_verify", "last_ts"
    )


def read_last_ts(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return int(fh.read().strip() or 0)
    except (OSError, ValueError):
        # First run, or a corrupt state file: start from the beginning. Splunk
        # dedupes nothing for us, but re-reading from 0 is safer than skipping.
        return 0


def write_last_ts(path: str, ts: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(str(ts))
    os.replace(tmp, path)  # atomic, so a crash mid-write cannot corrupt state


def fetch(url: str, timeout: int = 30) -> dict:
    # Bypass any configured HTTP proxy — the API is internal, and a corporate
    # proxy will typically return 403 for localhost.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    base = os.environ.get("GRYPE_VERIFY_URL", DEFAULT_URL).rstrip("/")
    limit = int(os.environ.get("GRYPE_VERIFY_LIMIT", DEFAULT_LIMIT))
    path = state_path()
    last_ts = read_last_ts(path)

    url = f"{base}/api/v1/checks?since={last_ts}&limit={limit}"
    try:
        payload = fetch(url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # Log to stderr (splunkd.log) and exit non-zero; Splunk retries next interval.
        print(f"grype_verify: failed to fetch {url}: {exc}", file=sys.stderr)
        return 1

    results = payload.get("results", [])
    if not results:
        return 0

    newest = last_ts
    try:
        for rec in results:
            # One JSON object per line — LINE_BREAKER in props.conf splits on newline.
            sys.stdout.write(json.dumps(rec, separators=(",", ":")) + "\n")
            ts = int(rec.get("timestamp", 0))
            newest = max(newest, ts)
        sys.stdout.flush()
    except BrokenPipeError:
        # Reader went away mid-write (Splunk restart, or a shell pipe closing).
        # Leave the watermark untouched so the unsent records are retried.
        print("grype_verify: output pipe closed, not advancing watermark", file=sys.stderr)
        return 1

    # Only advance state after the events are written, so a failure mid-write
    # re-sends rather than silently drops.
    if newest > last_ts:
        write_last_ts(path, newest)

    print(f"grype_verify: sent {len(results)} checks, watermark={newest}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
