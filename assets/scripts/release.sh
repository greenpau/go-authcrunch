#!/usr/bin/env bash
# Release only main and its exact annotated version tag.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cd "${script_dir}/../.."
kind=${1:-patch}
case "$kind" in patch|minor|check) ;; *) echo "Expected patch, minor, or check" >&2; exit 1 ;; esac

fail() { echo "Release stopped: $*" >&2; exit 1; }
skip_tests=false
if [ "$#" -gt 1 ]; then
    [ "$#" -eq 2 ] && [ "$2" = --skip-tests ] && [ "$kind" != check ] || \
        fail "usage: release.sh [patch|minor [--skip-tests]|check]"
    skip_tests=true
fi
clean_tree() {
    [ -z "$(git status --porcelain --untracked-files=all)" ] || fail "working tree and index must be clean"
}
branch=$(git symbolic-ref --quiet --short HEAD) || fail "detached HEAD"
[ "$branch" = main ] || fail "releases require main"
clean_tree
make version-check
[ "$kind" != check ] || exit 0

# Fetch is read-only for the worktree. Reject stale/diverged local main before bumping.
git fetch --no-tags origin main
git merge-base --is-ancestor FETCH_HEAD HEAD || fail "main is behind or diverged from origin/main"
go tool versioned -version
version=$("${PYTHON:-python3}" assets/scripts/version.py next --kind "$kind")
tag="v${version}"
if git show-ref --verify --quiet "refs/tags/${tag}"; then fail "tag ${tag} already exists locally"; fi
remote_tag=$(git ls-remote --tags origin "refs/tags/${tag}")
[ -z "$remote_tag" ] || fail "tag ${tag} already exists on origin"
clean_tree

go tool versioned "-${kind}"
make version-sync
[ "$(cat VERSION)" = "$version" ] || fail "versioned produced an unexpected version"
# Checked releases run the full gate once against the synchronized contents.
if [ "$skip_tests" = true ]; then
    echo "Skipping local ci-check (--skip-tests); GitHub release validation still runs."
else
    make ci-check
fi

# Stage only the version authority and its declared projections.
git diff --cached --quiet || fail "validation staged unexpected changes"
git add -- VERSION cmd/authdb/main.go cmd/authdbctl/main.go pkg/identity/database.go
git diff --quiet || fail "validation left unrelated tracked changes"
[ -z "$(git ls-files --others --exclude-standard)" ] || fail "validation left untracked files"
git diff --cached --quiet && fail "no version changes to commit"
git commit -m "ops: released ${tag}"
git tag -a "$tag" -m "$tag"
# Atomic push cannot publish one ref without the other and never pushes unrelated tags.
git push --atomic origin HEAD:refs/heads/main "refs/tags/${tag}"
echo "Released ${tag}"
