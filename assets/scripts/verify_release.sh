#!/usr/bin/env bash
# Validate the remote annotation against the exact commit tested by this run.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cd "${script_dir}/../.."
tag=${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}
commit=${GITHUB_SHA:?GITHUB_SHA is required}
fail() { echo "Release verification failed: $*" >&2; exit 1; }

"${PYTHON:-python3}" assets/scripts/version.py check --tag "$tag"
# actions/checkout can replace an annotated local tag with the event's commit
# SHA. Restore only that tag from origin; never change the checked-out commit.
git fetch --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}"
[ "$(git cat-file -t "refs/tags/${tag}")" = tag ] || fail "${tag} is not annotated on origin"
[ "$(git rev-parse HEAD)" = "$commit" ] || fail "HEAD does not match the workflow commit"
[ "$(git rev-parse "refs/tags/${tag}^{commit}")" = "$commit" ] || fail "${tag} does not point to the workflow commit"
echo "Verified annotated release tag ${tag} at ${commit}"
