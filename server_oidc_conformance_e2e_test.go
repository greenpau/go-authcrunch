// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authcrunch_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const foundationSuiteRevision = "e3b5558d6d5e0c17ab578a47b955fd3b405f902b"

func foundationWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal("encode private conformance state")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func foundationApplications(t *testing.T, callback string) ([]*oidc.OAuthApplicationConfig, map[string]any) {
	t.Helper()
	var applications []*oidc.OAuthApplicationConfig
	config := make(map[string]any)
	for _, name := range []string{"client", "client2", "client_secret_post"} {
		method := "client_secret_basic"
		if name == "client_secret_post" {
			method = name
		}
		client, err := oidcparser.NewOIDCClientConfigFromDirectives(name, []string{cfgutil.EncodeArgs([]string{"redirect_uris", callback}), "token_endpoint_auth_method " + method, "scopes openid profile email", "require_pkce off"})
		if err != nil {
			t.Fatal(err)
		}
		application, err := oidc.NewOAuthApplicationConfig(name, client)
		if err != nil {
			t.Fatal(err)
		}
		applications = append(applications, application)
		config[name] = map[string]any{"client_id": client.ClientID, "client_secret": client.ClientSecret, "scope": "openid profile email"}
	}
	return applications, config
}

func TestOIDCConformanceStaticRegistrations(t *testing.T) {
	applications, config := foundationApplications(t, "https://suite.example.test/test/a/local/callback")
	ids, secrets := map[string]bool{}, map[string]bool{}
	for _, app := range applications {
		client := app.Client
		if ids[client.ClientID] || secrets[client.ClientSecret] || client.ClientSecret == "" || client.RequirePKCE || client.SkipConsent {
			t.Fatal("invalid independent conformance registration")
		}
		ids[client.ClientID], secrets[client.ClientSecret] = true, true
		if config[app.Name].(map[string]any)["client_id"] != client.ClientID {
			t.Fatal("plan registration mismatch")
		}
	}
	file := filepath.Join(t.TempDir(), "applications.json")
	foundationWriteJSON(t, file, &authcrunch.Config{OAuthApplications: applications})
	var restored authcrunch.Config
	if err := restored.LoadFromJSONFile(file); err != nil {
		t.Fatal(err)
	}
	if got, err := restored.GetOAuthApplications(); err != nil || len(got) != 3 {
		t.Fatal("persisted conformance registrations invalid")
	}
}

// TestE2EServerOIDCFoundationPlans runs the unmodified Foundation runner. It is
// opt-in because Java, MongoDB, and the pinned suite are external prerequisites.
// Nonzero runner results remain failures, including warnings/review outcomes;
// this fixture never converts them into a certification claim.
func TestE2EServerOIDCFoundationPlans(t *testing.T) {
	suite := os.Getenv("AUTHCRUNCH_CONFORMANCE_SUITE")
	if suite == "" {
		t.Skip("set AUTHCRUNCH_CONFORMANCE_SUITE and the documented local tool paths to run the official Foundation plans")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	inside := func(path string) string {
		t.Helper()
		p, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		p, err = filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatal("conformance prerequisites must reside inside this repository")
		}
		return p
	}
	suite = inside(suite)
	tool := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing prerequisite %s", name)
		}
		p, err := filepath.Abs(value)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	java, mongod, python := tool("AUTHCRUNCH_CONFORMANCE_JAVA"), tool("AUTHCRUNCH_CONFORMANCE_MONGOD"), tool("AUTHCRUNCH_CONFORMANCE_PYTHON")
	for _, args := range [][]string{{"rev-parse", "HEAD"}, {"diff", "HEAD", "--exit-code"}} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", suite}, args...)...)
		data, err := cmd.Output()
		if err != nil {
			t.Fatal("suite checkout must be unmodified")
		}
		if args[0] == "rev-parse" && strings.TrimSpace(string(data)) != foundationSuiteRevision {
			t.Fatal("unexpected Foundation suite revision")
		}
	}
	output := os.Getenv("AUTHCRUNCH_CONFORMANCE_RESULTS")
	if output == "" {
		t.Fatal("set AUTHCRUNCH_CONFORMANCE_RESULTS to a new private directory inside the repository")
	}
	parent := inside(filepath.Dir(output))
	output = filepath.Join(parent, filepath.Base(output))
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal("result directory must be new", err)
	}
	t.Log("Foundation evidence directory:", output)
	candidate := map[string]any{"suite_revision": foundationSuiteRevision, "host": "public authcrunch.Server with local portal", "profiles": []string{"Basic OP", "Config OP", "Form Post OP code"}}
	if info, ok := debug.ReadBuildInfo(); ok {
		candidate["go_version"] = info.GoVersion
	}
	for _, args := range [][]string{{"rev-parse", "HEAD"}, {"diff", "HEAD", "--"}} {
		data, err := exec.CommandContext(t.Context(), "git", args...).Output()
		if err != nil {
			t.Fatal("record candidate revision")
		}
		if args[0] == "rev-parse" {
			candidate["commit"] = strings.TrimSpace(string(data))
		} else {
			digest := sha256.Sum256(data)
			candidate["tracked_diff_sha256"] = hex.EncodeToString(digest[:])
		}
	}
	// Include untracked source additions: HEAD plus a tracked diff alone does
	// not identify an uncommitted candidate with new tests or packages.
	paths, err := exec.CommandContext(t.Context(), "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").Output()
	if err != nil {
		t.Fatal("enumerate candidate source")
	}
	manifest := make(map[string]string)
	for path := range strings.SplitSeq(string(paths), "\x00") {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, path))
		if os.IsNotExist(err) {
			manifest[path] = "deleted"
			continue
		}
		if err != nil {
			t.Fatal("read candidate source")
		}
		digest := sha256.Sum256(data)
		manifest[path] = hex.EncodeToString(digest[:])
	}
	foundationWriteJSON(t, filepath.Join(output, "source-manifest.json"), manifest)
	foundationWriteJSON(t, filepath.Join(output, "candidate.json"), candidate)

	port := func() string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, p, _ := net.SplitHostPort(l.Addr().String())
		_ = l.Close()
		return p
	}
	mongoPort, javaPort := port(), port()
	start := func(name, executable string, args ...string) {
		t.Helper()
		log, err := os.OpenFile(filepath.Join(output, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, args...)
		cmd.Dir = suite
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			_ = log.Close()
			t.Fatal("start conformance prerequisite", err)
		}
		done := make(chan error, 1)
		go func() { err := cmd.Wait(); _ = log.Close(); done <- err }()
		t.Cleanup(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	dbdir := filepath.Join(output, "mongodb")
	if err := os.Mkdir(dbdir, 0700); err != nil {
		t.Fatal(err)
	}
	start("mongodb", mongod, "--dbpath", dbdir, "--bind_ip", "127.0.0.1", "--port", mongoPort, "--quiet")
	upstream, _ := url.Parse("http://127.0.0.1:" + javaPort)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, p, _ := net.SplitHostPort(r.Host)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Set("X-Forwarded-Port", p)
		r.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		r.Header.Set("X-Ssl-Protocol", "TLSv1.3")
		r.Header.Set("X-Ssl-Cipher", tls.CipherSuiteName(r.TLS.CipherSuite))
		r.Header.Set("Host", host)
		proxy.ServeHTTP(w, r)
	}))
	defer func() { front.CloseClientConnections(); front.Close() }()
	start("suite", java, "-Xmx2g", "-jar", filepath.Join(suite, "target/fapi-test-suite.jar"), "--spring.profiles.active=dev", "--server.address=127.0.0.1", "--server.port="+javaPort, "--spring.mongodb.uri=mongodb://127.0.0.1:"+mongoPort+"/authcrunch_conformance", "--openid.mongodb.targetFeatureCompatibilityVersion=7.0", "--fintechlabs.base_url="+front.URL, "--fintechlabs.base_mtls_url="+front.URL, "--logging.level.net.openid.conformance=INFO")
	readyCtx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(readyCtx, http.MethodGet, front.URL+"/api/server", nil)
		resp, err := front.Client().Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				break
			}
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("Foundation suite did not become ready; inspect private suite.log")
		case <-time.After(200 * time.Millisecond):
		}
	}
	portalServer := httptest.NewUnstartedServer(nil)
	defer portalServer.Close()
	issuer := "https://" + portalServer.Listener.Addr().String() + "/auth"
	username, password := "conformance", oidc.GenerateClientSecret()
	userFile := filepath.Join(output, "users.json")
	db, err := identity.NewDatabase(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: username, FullName: "Conformance User", Email: "conformance@example.test", Password: password, Roles: []string{"authp/user"}}}); err != nil {
		t.Fatal("provision conformance identity")
	}
	key := filepath.Join(output, "oidc.pem")
	if err := oidc.GenerateSigningKeyFile(key); err != nil {
		t.Fatal(err)
	}
	alias := "authcrunch-local"
	applications, plan := foundationApplications(t, front.URL+"/test/a/"+alias+"/callback")
	cfg := &authcrunch.Config{OAuthApplications: applications, IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": userFile}}}}
	portalCfg := &authn.PortalConfig{Name: "conformance", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "portal", "sign-verify", "from", "file", filepath.Join(root, "testdata/rskeys/test_2_pri.pem")})}}
	if err := cfg.ConfigureOIDCProvider(portalCfg, []string{cfgutil.EncodeArgs([]string{"issuer", issuer}), "realms local", cfgutil.EncodeArgs([]string{"signing", "key", "files", key}), "applications client client2 client_secret_post"}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddAuthenticationPortal(portalCfg); err != nil {
		t.Fatal(err)
	}
	foundationWriteJSON(t, filepath.Join(output, "deployment.private.json"), cfg)
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("encode deployment")
	}
	var redacted map[string]any
	if json.Unmarshal(encoded, &redacted) != nil {
		t.Fatal("decode deployment")
	}
	var redact func(any)
	redact = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for name, child := range v {
				if name == "client_secret" {
					v[name] = "REDACTED"
				} else {
					redact(child)
				}
			}
		case []any:
			for _, child := range v {
				redact(child)
			}
		}
	}
	redact(redacted)
	foundationWriteJSON(t, filepath.Join(output, "deployment.redacted.json"), redacted)

	runtime, err := authcrunch.NewServer(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { portalServer.CloseClientConnections(); portalServer.Close(); _ = runtime.Close() }()
	portal, err := runtime.GetPortalByName("conformance")
	if err != nil {
		t.Fatal(err)
	}
	portalServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("conformance portal request failed")
		}
	})
	portalServer.StartTLS()
	portalClient := portalServer.Client()
	portalClient.Timeout = 10 * time.Second
	resp, err := portalClient.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatal("conformance discovery unavailable")
	}
	if err := os.WriteFile(filepath.Join(output, "discovery.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	plan["alias"], plan["description"] = alias, "AuthCrunch local candidate; unmodified Foundation suite "+foundationSuiteRevision
	plan["server"] = map[string]any{"discoveryUrl": issuer + "/.well-known/openid-configuration"}
	plan["browser"] = []any{map[string]any{"match": issuer + "*", "tasks": []any{
		map[string]any{"task": "Login identity", "optional": true, "match": issuer + "/login*", "commands": [][]any{{"text", "name", "username", username}, {"click", "class", "app-btn-pri"}}},
		map[string]any{"task": "Password", "optional": true, "match": issuer + "/sandbox/*", "commands": [][]any{{"text", "name", "secret", password}, {"click", "name", "submit"}}},
		map[string]any{"task": "Consent", "optional": true, "match": issuer + "/oidc/continue*", "commands": [][]any{{"click", "name", "decision"}}},
		map[string]any{"task": "Verify callback", "optional": true, "match": front.URL + "/test/*/callback*", "commands": [][]any{{"wait", "id", "submission_complete", 10}}},
	}}}
	// The official browser command records actual page source against the
	// suite's pending visual-review placeholder. It does not mark it PASSED.
	browser := plan["browser"].([]any)
	fresh := browser[0].(map[string]any)
	freshTasks := fresh["tasks"].([]any)
	login := freshTasks[0].(map[string]any)
	login["commands"] = append([][]any{{"wait", "xpath", "//*", 10, "(?i)username", "update-image-placeholder-optional"}}, login["commands"].([][]any)...)
	overrides := map[string]any{}
	for _, name := range []string{"oidcc-ensure-registered-redirect-uri", "oidcc-ensure-redirect-uri-in-authorization-request", "oidcc-redirect-uri-query-added", "oidcc-redirect-uri-query-mismatch"} {
		overrides[name] = map[string]any{"browser": []any{map[string]any{"match": issuer + "*", "tasks": []any{map[string]any{"task": "Capture redirect rejection", "match": issuer + "/oidc/authorize*", "commands": [][]any{{"wait", "xpath", "//*", 10, "invalid_request", "update-image-placeholder"}}}}}}}
	}
	plan["override"] = overrides
	planFile := filepath.Join(output, "plan.private.json")
	foundationWriteJSON(t, planFile, plan)
	results := filepath.Join(output, "results")
	if err := os.Mkdir(results, 0700); err != nil {
		t.Fatal(err)
	}
	args := []string{filepath.Join(suite, "scripts/run-test-plan.py"), "--no-parallel", "--export-dir", results,
		"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]", planFile,
		"oidcc-config-certification-test-plan", planFile,
		"oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]", planFile}
	if os.Getenv("AUTHCRUNCH_CONFORMANCE_CONFIG_ONLY") == "1" {
		args = append(args[:4], "oidcc-config-certification-test-plan", planFile)
	}
	runnerCtx, cancelRunner := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancelRunner()
	runner := exec.CommandContext(runnerCtx, python, args...)
	runner.Dir = suite
	runner.Env = append(os.Environ(), "CONFORMANCE_DEV_MODE=1", "CONFORMANCE_SERVER="+front.URL+"/", "CONFORMANCE_SERVER_MTLS="+front.URL+"/")
	log, err := os.OpenFile(filepath.Join(output, "runner.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	runner.Stdout, runner.Stderr = log, log
	err = runner.Run()
	_ = log.Close()
	runnerExitCode := -1
	if runner.ProcessState != nil {
		runnerExitCode = runner.ProcessState.ExitCode()
	}
	status := map[string]any{"suite_revision": foundationSuiteRevision, "runner_exit_code": runnerExitCode, "runner_error": fmt.Sprint(err), "config_only": os.Getenv("AUTHCRUNCH_CONFORMANCE_CONFIG_ONLY") == "1", "finished_at": time.Now().UTC().Format(time.RFC3339)}
	foundationWriteJSON(t, filepath.Join(output, "execution.json"), status)
	if err != nil {
		t.Fatal("Foundation runner returned nonzero; retain and review every result in", output)
	}
}
