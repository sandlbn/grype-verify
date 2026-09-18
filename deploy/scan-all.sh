#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Intel Corporation
#
# Re-scan every SBOM in a directory and record each result.
#
# Intended to be driven by a systemd timer or cron entry. Configuration comes
# from the environment so the same script works for both; see grype-verify.env.
#
#   SBOM_DIR            directory to search for *.spdx.json  (default /var/lib/grype-verify/sboms)
#   GRYPE_CHECKS_DB     SQLite results database              (default /var/lib/grype-verify/grype-checks.db)
#   GRYPE_DB_CACHE_DIR  grype vulnerability DB cache         (default /var/lib/grype-verify/grype-db)
#   SARIF_DIR           if set, write <name>.sarif per SBOM into this directory
#   FAIL_ON             severity threshold                    (default high)
#   GRYPE_VERIFY_BIN    path to the binary                    (default grype-verify on PATH)

set -uo pipefail

SBOM_DIR="${SBOM_DIR:-/var/lib/grype-verify/sboms}"
GRYPE_CHECKS_DB="${GRYPE_CHECKS_DB:-/var/lib/grype-verify/grype-checks.db}"
GRYPE_DB_CACHE_DIR="${GRYPE_DB_CACHE_DIR:-/var/lib/grype-verify/grype-db}"
FAIL_ON="${FAIL_ON:-high}"
GRYPE_VERIFY_BIN="${GRYPE_VERIFY_BIN:-grype-verify}"
export GRYPE_CHECKS_DB GRYPE_DB_CACHE_DIR

if [[ ! -d "$SBOM_DIR" ]]; then
    echo "scan-all: SBOM_DIR does not exist: $SBOM_DIR" >&2
    exit 1
fi

shopt -s nullglob
sboms=("$SBOM_DIR"/*.spdx.json)
if [[ ${#sboms[@]} -eq 0 ]]; then
    echo "scan-all: no *.spdx.json files found in $SBOM_DIR" >&2
    exit 1
fi

[[ -n "${SARIF_DIR:-}" ]] && mkdir -p "$SARIF_DIR"

# Track the worst outcome across all SBOMs, but never abort early: one vulnerable
# component must not stop the rest from being scanned and recorded.
worst=0
for sbom in "${sboms[@]}"; do
    echo "scan-all: scanning $sbom"

    sarif_args=()
    if [[ -n "${SARIF_DIR:-}" ]]; then
        name="$(basename "$sbom" .spdx.json)"
        sarif_args=(--sarif-file "${SARIF_DIR}/${name}.sarif")
    fi

    "$GRYPE_VERIFY_BIN" scan "$sbom" \
        --output table \
        --fail-on "$FAIL_ON" \
        "${sarif_args[@]}"
    rc=$?

    case "$rc" in
        0) ;;                                   # clean
        2) [[ $worst -lt 2 ]] && worst=2 ;;     # vulnerabilities at/above threshold
        *) worst=1 ;;                           # tool error outranks a finding
    esac
done

echo "scan-all: finished, worst result code = $worst"
exit "$worst"
