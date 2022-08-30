.PHONY: test ctest covdir coverage docs linter qtest clean dep release license envvar templates
APP_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif

all: envvar build
	@echo "$@: complete"

envvar:
	@echo "Version: $(APP_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"

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

linter:
	@echo "Running lint checks"
	@golint -set_exit_status ./...
	@echo "$@: complete"

gtest:
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out ./...
	@echo "$@: complete"

test: templates envvar covdir linter gtest coverage
	@echo "$@: complete"

ctest: templates covdir linter
	@richgo version || go install github.com/kyoh86/richgo@latest
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./...
	@echo "$@: complete"

covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage
	@echo "$@: complete"

coverage:
	@#go tool cover -help
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./...
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@echo "$@: complete"

ui-templates:
	@./assets/scripts/generate_ui.sh
	@echo "$@: complete"

email-templates:
	@./assets/scripts/generate_email_templates.sh
	@echo "$@: complete"

templates: ui-templates email-templates license
	@echo "$@: complete"

docs:
	@mkdir -p .doc
	@go doc -all > .doc/index.txt
	@cat .doc/index.txt
	@echo "$@: complete"

clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/
	@echo "$@: complete"

qtest: covdir
	@echo "Perform quick tests ..."
	@#time richgo test -v -coverprofile=.coverage/coverage.out internal/tag/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/util/data/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewConfig ./*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewServer ./*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/registry/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/waf/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestAuthorize ./pkg/authz/validator/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out  -run TestAddProviders ./pkg/messaging/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/messaging/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/credentials/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/errors/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/requests/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authn/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewPortal ./pkg/authn/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestServeHTTP ./pkg/authn/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestFactory ./pkg/authn/cookie/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewSingleSignOnProviderConfig ./pkg/sso/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewSingleSignOnProvider ./pkg/sso/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestParseRequestURL ./pkg/sso/request*.go
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestGetMetadata ./pkg/sso/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestValidateJwksKey ./pkg/authn/backends/oauth2/jwks*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestTransformData ./pkg/authn/transformer/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authn/icons/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/idp/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/idp/saml/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/idp/oauth/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewJwksKeyFromRSAPublicKeyPEM ./pkg/idp/oauth/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewIdentityProviderConfig ./pkg/idp/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authn/ui/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/ids/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/ids/local/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/ids/ldap/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authz/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewGatekeeper ./pkg/authz/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestAuthenticate ./pkg/authz/*.go
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/util/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/kms/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/acl/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run NewAclRule ./pkg/acl/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestCustomAccessList ./pkg/acl/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestNewAclRuleCondition ./pkg/acl/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out -run TestMatchAclRuleCondition ./pkg/acl/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/user/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authproxy/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/identity/...
	@#time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./pkg/authn/backends/...
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@#go tool cover -func=.coverage/coverage.out | grep -v "100.0"
	@go tool cover -func=.coverage/coverage.out
	@echo "$@: complete"

dep:
	@echo "Making dependencies check ..."
	@golint || go install golang.org/x/lint/golint@latest
	@go install github.com/kyoh86/richgo@latest
	@versioned || go install github.com/greenpau/versioned/cmd/versioned@latest
	@echo "$@: complete"

license:
	@versioned || go install github.com/greenpau/versioned/cmd/versioned@latest
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2022 -filepath=$$f; done
	@#for f in `find ./ -type f -name '*.go'`; do versioned -striplicense -filepath=$$f; done
	@echo "$@: complete"

release:
	@echo "Making release"
	@go mod tidy
	@go mod verify
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
