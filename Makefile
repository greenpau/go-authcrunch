APP_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif
TEST_DIR:="./..."

all: info build
	@echo "$@: complete"

.PHONY: info
info:
	@echo "Version: $(APP_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"

.PHONY: build
build: templates
	@mkdir -p bin/
	@rm -rf ./bin/*
	@versioned -sync ./pkg/identity/database.go
	@CGO_ENABLED=0 go build -o ./bin/authdbctl $(VERBOSE) \
		-ldflags="-w -s \
		-X main.appVersion=$(APP_VERSION) \
		-X main.gitBranch=$(GIT_BRANCH) \
		-X main.gitCommit=$(GIT_COMMIT) \
		-X main.buildUser=$(BUILD_USER) \
		-X main.buildDate=$(BUILD_DATE)" \
		-gcflags="all=-trimpath=$(GOPATH)/src" \
		-asmflags="all=-trimpath $(GOPATH)/src" \
		cmd/authdbctl/*.go
	@./bin/authdbctl --version
	@./bin/authdbctl --help
	@echo "$@: complete"

.PHONY: linter
linter:
	@echo "Running lint checks"
	@golint -set_exit_status $(TEST_DIR)
	@echo "$@: complete"

.PHONY: gtest
gtest:
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out $(TEST_DIR)
	@echo "$@: complete"

.PHONY: test
test: templates info covdir linter gtest coverage
	@echo "$@: complete"


.PHONY: install-test-tools
install-test-tools:
	@echo "$@: started"
	@richgo version || go install github.com/kyoh86/richgo@latest
	@tparse -v || go install github.com/mfridman/tparse@latest
	@go-test-report version || go install github.com/vakenbolt/go-test-report@latest
	@echo "$@: complete"

.PHONY: run-tests
run-tests:
	@echo "$@: started"
	@go test -json $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out $(TEST_DIR) | tee .coverage/test_output.jsonl
	@echo "$@: complete"


#QUICK_TEST_DIR="./pkg/kms/..."
# QUICK_TEST_DIR="./pkg/authz/validator"
QUICK_TEST_DIR="./pkg/authn"
# QUICK_TEST_PATTERN_RUN="-run"
# QUICK_TEST_PATTERN="TestAuthorizationSources"
.PHONY: run-quick-tests
run-quick-tests:
	@echo "$@: started"
	@go test -json $(VERBOSE) -coverprofile=.coverage/coverage.out $(QUICK_TEST_PATTERN_RUN) $(QUICK_TEST_PATTERN) $(QUICK_TEST_DIR) | tee .coverage/test_output.jsonl
	@echo "$@: complete"

.PHONY: run-reports
run-reports:
	@echo "$@: started"
	@cat .coverage/test_output.jsonl | go-test-report -o .coverage/test_output.html
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@echo "$@: complete"

.PHONY: ctest
ctest: templates covdir linter install-test-tools run-tests run-reports
	@if grep -q '"Action":"fail"' .coverage/test_output.jsonl; then \
		echo "ERROR: Go tests failed! See .coverage/test_output.jsonl for details."; \
		exit 1; \
	fi
	@echo "$@: complete"

.PHONY: covdir
covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage
	@rm -rf .coverage/{coverage,test_output}.{html,jsonl,out}
	@echo "$@: complete"

.PHONY: coverage
coverage:
	@#go tool cover -help
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out $(TEST_DIR)
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "$@: complete"

.PHONY: templates
templates: license
	@echo "$@: complete"

.PHONY: docs
docs:
	@mkdir -p .doc
	@go doc -all > .doc/index.txt
	@cat .doc/index.txt
	@echo "$@: complete"

.PHONY: clean
clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/
	@echo "$@: complete"

.PHONY: qtest
qtest: covdir install-test-tools run-quick-tests run-reports
	@if grep -q '"Action":"fail"' .coverage/test_output.jsonl; then \
		echo "ERROR: Go tests failed! See .coverage/test_output.jsonl for details."; \
		exit 1; \
	fi
	@echo "$@: complete"

.PHONY: dep
dep:
	@echo "Making dependencies check ..."
	@golint || go install golang.org/x/lint/golint@latest
	@go install github.com/kyoh86/richgo@latest
	@versioned || go install github.com/greenpau/versioned/cmd/versioned@latest
	@echo "$@: complete"

.PHONY: license
license:
	@versioned || go install github.com/greenpau/versioned/cmd/versioned@latest
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=$$f; done
	@#for f in `find ./ -type f -name '*.go'`; do versioned -striplicense -filepath=$$f; done
	@versioned -toc -filepath cmd/authdbctl/README.md
	@echo "$@: complete"

.PHONY: upgrade
upgrade:
	@echo "Making upgrade"
	@go get -u $(TEST_DIR)
	@go mod tidy
	@echo "$@: complete"

.PHONY: release
release:
	@echo "Making release"
	@go mod tidy;
	@go mod verify;
	@if [ $(GIT_BRANCH) != "main" ]; then echo "cannot release to non-main branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@versioned -patch
	@echo "Patched version"
	@git add VERSION
	@versioned -sync ./cmd/authdbctl/main.go
	@versioned -sync ./pkg/identity/database.go
	@git add cmd/authdbctl/main.go ./pkg/identity/database.go
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
