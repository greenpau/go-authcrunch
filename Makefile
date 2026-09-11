SHELL := /bin/bash
.DEFAULT_GOAL := all

APP_VERSION := $(shell head -1 VERSION)
GIT_COMMIT := $(shell git describe --dirty --always)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILD_USER := $(shell whoami)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
PYTHON ?= python3
TEST ?= .
TEST_DIR ?= ./...
QUICK_TEST_DIR ?= ./pkg/system
COVERAGE_DIR ?= .coverage
MINIMUM_COVERAGE ?= 1
export TEST TEST_DIR QUICK_TEST_DIR COVERAGE_DIR MINIMUM_COVERAGE
export APP_VERSION GIT_COMMIT GIT_BRANCH BUILD_USER BUILD_DATE
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: all info build linter dep install-test-tools test run-tests qtest run-quick-tests run-reports test-ui test-automation ci-check version-check version-sync artifact-id templates license docs clean upgrade mod-tidy release minor-release release-git-check release-update-version release-git-commit

all: info build

info:
	@echo "Version: $$APP_VERSION, Branch: $$GIT_BRANCH, Revision: $$GIT_COMMIT"
	@echo "Built on $$BUILD_DATE by $$BUILD_USER"

# Validation and builds never rewrite source, licenses, or module manifests.
build: version-check
	@mkdir -p bin
	@CGO_ENABLED=0 go build -mod=readonly -trimpath -o bin/authdbctl \
		-ldflags="-w -s \
		-X main.appVersion=$$APP_VERSION \
		-X main.gitBranch=$$GIT_BRANCH \
		-X main.gitCommit=$$GIT_COMMIT \
		-X main.buildUser=$$BUILD_USER \
		-X main.buildDate=$$BUILD_DATE" ./cmd/authdbctl
	@./bin/authdbctl --version
	@./bin/authdbctl --help

linter:
	@go tool golint -set_exit_status ./...

# Tools are pinned by go.mod/go.sum; no global installation is required.
dep:
	@go mod download
	@go mod verify
	@$(MAKE) install-test-tools
	@go tool versioned -version
	@go tool golint -h >/dev/null 2>&1

install-test-tools:
	@go tool tested version

test: run-tests

run-tests:
	@rm -rf .coverage
	@go tool tested run --output-dir "$$COVERAGE_DIR" \
		--title "AuthCrunch Go tests" --minimum-coverage "$$MINIMUM_COVERAGE" \
		-- -mod=readonly -race -count=1 -v -run "$$TEST" $$TEST_DIR

qtest: run-quick-tests

run-quick-tests:
	@$(MAKE) run-tests TEST_DIR="$$QUICK_TEST_DIR" COVERAGE_DIR="$$COVERAGE_DIR/quick"

run-reports:
	@go tool tested report --output-dir "$$COVERAGE_DIR" --title "AuthCrunch Go tests"

test-ui:
	@node --test --test-reporter=spec pkg/authn/ui/testdata/refresh_client_test.cjs

test-automation:
	@$(PYTHON) -m unittest discover -s assets/scripts/tests -p '*_test.py' -v

# Recursive invocations deliberately serialize gates, even with make -j.
ci-check:
	@$(MAKE) version-check
	@$(MAKE) test-automation
	@$(MAKE) linter
	@$(MAKE) test TEST=. TEST_DIR=./... COVERAGE_DIR=.coverage MINIMUM_COVERAGE=1
	@$(MAKE) test-ui
	@$(MAKE) build

version-check:
	@$(PYTHON) assets/scripts/version.py check

version-sync:
	@$(PYTHON) assets/scripts/version.py sync

artifact-id:
	@$(PYTHON) assets/scripts/version.py artifact

# Explicit maintenance actions are separate from test/build entry points.
templates: license

license:
	@find . -type f -name '*.go' -not -path './vendor/*' -not -path './tmp/*' -not -path './.tmp/*' \
		-exec go tool versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath={} \;
	@go tool versioned -toc -filepath cmd/authdbctl/README.md

docs:
	@mkdir -p .doc
	@go doc -all > .doc/index.txt
	@cat .doc/index.txt

clean:
	@rm -rf .doc .coverage bin

upgrade:
	@go get -u ./...
	@go mod tidy

mod-tidy:
	@go mod tidy
	@go mod verify

# Only run these publishing commands when a release is explicitly requested.
release:
	@bash assets/scripts/release.sh patch

minor-release:
	@bash assets/scripts/release.sh minor

release-git-check:
	@bash assets/scripts/release.sh check

# Old partial entry points could bypass release checks and publish unrelated tags.
release-update-version release-git-commit:
	@echo "Use make release (patch) or make minor-release for the complete checked workflow." >&2
	@exit 1
