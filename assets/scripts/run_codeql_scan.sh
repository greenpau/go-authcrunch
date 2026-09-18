#!/bin/bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
codeql_cmd="${CODEQL:-codeql}"
if ! command -v "$codeql_cmd" >/dev/null 2>&1; then
  printf 'CodeQL CLI not found: %s\n' "$codeql_cmd" >&2
  exit 1
fi

if [[ -n "${CODEQL_OUTPUT_DIR:-}" ]]; then
  mkdir -p "$CODEQL_OUTPUT_DIR"
  output_dir="$(cd -- "$CODEQL_OUTPUT_DIR" && pwd)"
else
  mkdir -p .coverage/codeql
  output_dir="$(mktemp -d "$repo_root/.coverage/codeql/scan.XXXXXXXX")"
fi

"$codeql_cmd" pack install .github/codeql/queries
"$codeql_cmd" pack download codeql/go-queries
"$codeql_cmd" database create "$output_dir/database" \
  --language=go --source-root="$repo_root" \
  --codescanning-config="$repo_root/.github/codeql/codeql-config.yml" \
  --command='go build -mod=readonly ./...'
"$codeql_cmd" database analyze "$output_dir/database" \
  --threads=2 --ram=5922 --format=sarif-latest \
  --output="$output_dir/results.sarif"
"$codeql_cmd" database interpret-results "$output_dir/database" \
  --format=csv --output="$output_dir/results.csv"

printf 'CodeQL scan results: %s\n' "$output_dir"
