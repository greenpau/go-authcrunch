#!/bin/bash
set -e

export CODEQL_SCAN_ID=$(date "+%Y%m%d_%H%M%S")

printf "CodeQL Scan ID: ${CODEQL_SCAN_ID}\n";

mkdir -p $HOME/.local/codeql/databases
cd $HOME/.local/codeql/databases
codeql database create \
  --language="go" \
  --source-root="${GOPATH}/src/github.com/greenpau/go-authcrunch" \
  -- ./go-authcrunch-${CODEQL_SCAN_ID}

cd $HOME/.local/codeql
codeql database run-queries --ram=5922 --threads=2 --verbose \
  --additional-packs . \
  -- ./databases/go-authcrunch-${CODEQL_SCAN_ID} \
  ./queries-go/ql/src/codeql-suites/go-code-scanning.qls

cd $HOME/.local/codeql
mkdir -p ./results/go-authcrunch
codeql database interpret-results --format csv \
  --output ./results/go-authcrunch/codeql_results_${CODEQL_SCAN_ID}.csv \
  -- ./databases/go-authcrunch-${CODEQL_SCAN_ID}

printf "CodeQL Scan Results (CSV): "`pwd`"/results/go-authcrunch/codeql_results_${CODEQL_SCAN_ID}.csv\n"

codeql database interpret-results --format sarif-latest \
  --output ./results/go-authcrunch/codeql_results_${CODEQL_SCAN_ID}_sarif.json \
  -- ./databases/go-authcrunch-${CODEQL_SCAN_ID}

printf "CodeQL Scan Results (SARIF): "`pwd`"/results/go-authcrunch/codeql_results_${CODEQL_SCAN_ID}_sarif.json\n"
