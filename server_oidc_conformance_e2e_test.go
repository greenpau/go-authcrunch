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
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"math/big"
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
		client, err := oidcparser.NewOIDCClientConfigFromDirectives(name, []string{cfgutil.EncodeArgs([]string{"redirect_uri", callback}), "token_endpoint_auth_method " + method, "scopes openid profile email address phone offline_access", "require_pkce off"})
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
		cmd.Env = foundationRunnerEnvironment(output, "", "", "")
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
	ca := filepath.Join(output, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(output, "trust.p12")
	keytool := exec.CommandContext(t.Context(), filepath.Join(filepath.Dir(java), "keytool"), "-importcert", "-noprompt", "-alias", "local-conformance", "-file", ca, "-keystore", trust, "-storepass", "conformance", "-storetype", "PKCS12")
	if _, err := keytool.CombinedOutput(); err != nil {
		t.Fatal("create suite TLS trust store", err)
	}
	start("suite", java, "-Xmx2g", "-Djava.io.tmpdir="+output, "-Djavax.net.ssl.trustStore="+trust, "-Djavax.net.ssl.trustStorePassword=conformance", "-jar", filepath.Join(suite, "target/fapi-test-suite.jar"), "--spring.profiles.active=dev", "--fintechlabs.makeDummyUserAdminInDevMode=false", "--server.address=127.0.0.1", "--server.port="+javaPort, "--spring.mongodb.uri=mongodb://127.0.0.1:"+mongoPort+"/authcrunch_conformance", "--openid.mongodb.targetFeatureCompatibilityVersion=7.0", "--fintechlabs.base_url="+front.URL, "--fintechlabs.base_mtls_url="+front.URL, "--logging.level.net.openid.conformance=INFO")
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
	tokenReq, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL+"/api/token", strings.NewReader("{}"))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenResp, err := front.Client().Do(tokenReq)
	if err != nil {
		t.Fatal("create local suite API token", err)
	}
	var suiteToken map[string]any
	tokenErr := json.NewDecoder(tokenResp.Body).Decode(&suiteToken)
	_ = tokenResp.Body.Close()
	if tokenErr != nil || tokenResp.StatusCode != 201 {
		t.Fatal("create local suite API token failed")
	}
	foundationWriteJSON(t, filepath.Join(output, "suite-token.private.json"), suiteToken)
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
	// These are explicit synthetic fixture attributes, never defaults for users.
	for _, u := range db.Users {
		u.Name = &identity.Name{First: "Conformance", Last: "User"}
		u.Profile = &identity.Profile{GivenName: "Conformance", FamilyName: "User", MiddleName: "Local", Nickname: "Test", ProfileURL: "https://example.test/conformance", Picture: "https://example.test/avatar.png", Website: "https://example.test", Gender: "unspecified", Birthdate: "2000-01-01", Zoneinfo: "America/New_York", Locale: "en-US", UpdatedAt: 1700000000, PhoneNumber: "+1 202-555-0100", PhoneNumberVerified: new(false), Address: &identity.Address{Formatted: "1 Example Street, Testville", StreetAddress: "1 Example Street", Locality: "Testville", Region: "Test", PostalCode: "00000", Country: "US"}}
	}
	foundationWriteJSON(t, userFile, db)
	key := filepath.Join(output, "oidc.pem")
	if err := oidc.GenerateSigningKeyFile(key); err != nil {
		t.Fatal(err)
	}
	alias := "authcrunch-local"
	applications, plan := foundationApplications(t, front.URL+"/test/a/"+alias+"/callback")
	cfg := &authcrunch.Config{OAuthApplications: applications, IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": userFile}}}}
	portalCfg := &authn.PortalConfig{Name: "conformance", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: []string{cfgutil.EncodeArgs([]string{"crypto", "key", "portal", "sign-verify", "from", "file", filepath.Join(root, "testdata/rskeys/test_2_pri.pem")})}}
	if err := cfg.ConfigureOIDCProvider(portalCfg, []string{cfgutil.EncodeArgs([]string{"issuer", issuer}), "realms local", cfgutil.EncodeArgs([]string{"signing", "key", "files", key}), "applications client client2 client_secret_post", "acr urn:authcrunch:password pwd"}); err != nil {
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
	plan["browser"], plan["override"] = foundationBrowserConfiguration(issuer, front.URL, username, password)
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
	runner.Dir = output
	runner.Env = foundationRunnerEnvironment(output, front.URL, ca, suiteToken["token"].(string))
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
	foundationCollectEvidence(t, output, front.URL, front.Client(), runnerExitCode)
	if err != nil {
		t.Fatal("Foundation runner returned nonzero; retain and review every result in", output)
	}
}

// A placeholder's presence does not identify the evidence it requests. Keep
// login captures scoped to reauthentication modules: Request Object tests can
// offer an error-page placeholder while accepting a successful callback.
func foundationBrowserConfiguration(issuer, suiteURL, username, password string) ([]any, map[string]any) {
	loginBrowser := func(captureLogin bool) []any {
		commands := [][]any{{"text", "name", "username", username}, {"click", "class", "app-btn-pri"}}
		if captureLogin {
			// The first login need not have a placeholder; the fresh-login
			// step does. Attaching actual page source leaves its REVIEW intact.
			commands = append([][]any{{"wait", "xpath", "//*", 10, "(?i)username", "update-image-placeholder-optional"}}, commands...)
		}
		return []any{map[string]any{"match": issuer + "*", "tasks": []any{
			map[string]any{"task": "Login identity", "optional": true, "match": issuer + "/login*", "commands": commands},
			map[string]any{"task": "Password", "optional": true, "match": issuer + "/sandbox/*", "commands": [][]any{{"text", "name", "secret", password}, {"click", "name", "submit"}}},
			map[string]any{"task": "Consent", "optional": true, "match": issuer + "/oidc/*", "commands": [][]any{{"click", "name", "decision"}}},
			map[string]any{"task": "Verify callback", "optional": true, "match": suiteURL + "/test/*/callback*", "commands": [][]any{{"wait", "id", "submission_complete", 10}}},
		}}}
	}
	overrides := map[string]any{}
	for _, name := range []string{"oidcc-prompt-login", "oidcc-max-age-1"} {
		overrides[name] = map[string]any{"browser": loginBrowser(true)}
	}
	for _, name := range []string{"oidcc-ensure-registered-redirect-uri", "oidcc-ensure-redirect-uri-in-authorization-request", "oidcc-redirect-uri-query-added", "oidcc-redirect-uri-query-mismatch"} {
		overrides[name] = map[string]any{"browser": []any{map[string]any{"match": issuer + "*", "tasks": []any{map[string]any{"task": "Capture redirect rejection", "match": issuer + "/oidc/authorize*", "commands": [][]any{{"wait", "xpath", "//*", 10, "invalid_request", "update-image-placeholder"}}}}}}}
	}
	return loginBrowser(false), overrides
}

// Explicit local trust and API authentication keep the official runner's TLS
// checks enabled. Inherited developer switches must not suppress outcomes.
func foundationRunnerEnvironment(output, base, ca, token string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "CONFORMANCE_") {
			continue
		}
		switch key {
		case "DISABLE_SSL_VERIFY", "EXTERNAL_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "SSL_CERT_DIR", "SSL_CERT_FILE", "PYTHONPATH", "PYTHONHOME", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "TMPDIR":
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "TMPDIR="+output, "PYTHONDONTWRITEBYTECODE=1", "NO_PROXY=127.0.0.1,localhost")
	if base != "" {
		env = append(env, "CONFORMANCE_SERVER="+base+"/", "CONFORMANCE_SERVER_MTLS="+base+"/", "CONFORMANCE_TOKEN="+token, "SSL_CERT_FILE="+ca, "CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000", "CONFORMANCE_RESTART_RETRIES=0")
	}
	return env
}

func TestOIDCConformanceRunnerTrust(t *testing.T) {
	t.Setenv("CONFORMANCE_DEV_MODE", "1")
	t.Setenv("DISABLE_SSL_VERIFY", "1")
	t.Setenv("CONFORMANCE_EXPECTED_FAILURES", "all")
	t.Setenv("HTTPS_PROXY", "https://proxy.invalid")
	env := foundationRunnerEnvironment(t.TempDir(), "https://suite.test", "local-ca.pem", "test-token")
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"CONFORMANCE_DEV_MODE=", "DISABLE_SSL_VERIFY=", "CONFORMANCE_EXPECTED_FAILURES=", "HTTPS_PROXY="} {
		if strings.Contains(joined, forbidden) {
			t.Fatal("inherited conformance bypass")
		}
	}
	if !strings.Contains(joined, "SSL_CERT_FILE=local-ca.pem") || !strings.Contains(joined, "CONFORMANCE_TOKEN=test-token") {
		t.Fatal("missing TLS trust or suite authentication")
	}
}

// Collect each original outcome and signed export, including unfinished modules.
// This does not replace the runner's result or promote visual REVIEW to PASSED.
func foundationCollectEvidence(t *testing.T, output, base string, client *http.Client, exit int) {
	t.Helper()
	client.Timeout = 20 * time.Second
	read := func(path string) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("collect official evidence", err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
		if err != nil || response.StatusCode != 200 || len(data) == 32<<20 {
			t.Fatal("incomplete official evidence", path)
		}
		return data
	}
	jsonGet := func(path string, target any) {
		t.Helper()
		if json.Unmarshal(read(path), target) != nil {
			t.Fatal("invalid official evidence JSON", path)
		}
	}
	var jwks struct{ Keys []struct{ Kty, N, E string } }
	jwksBytes := read("/jwks")
	if json.Unmarshal(jwksBytes, &jwks) != nil {
		t.Fatal("invalid suite JWKS")
	}
	if err := os.WriteFile(filepath.Join(output, "suite-jwks.json"), jwksBytes, 0600); err != nil {
		t.Fatal(err)
	}
	var keys []*rsa.PublicKey
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			t.Fatal("invalid suite modulus")
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			t.Fatal("invalid suite exponent")
		}
		keys = append(keys, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())})
	}
	var listing struct {
		Data []struct {
			ID string `json:"_id"`
		}
	}
	jsonGet("/api/plan?length=1000", &listing)
	outcomes := map[string]int{}
	var modules []map[string]any
	var pending []string
	verified, visuals := 0, 0
	exports := filepath.Join(output, "exports")
	if err := os.Mkdir(exports, 0700); err != nil {
		t.Fatal(err)
	}
	for _, listed := range listing.Data {
		var plan struct {
			Name    string `json:"planName"`
			Modules []struct {
				TestModule string
				Instances  []string
			}
		}
		raw := read("/api/plan/" + listed.ID)
		if json.Unmarshal(raw, &plan) != nil {
			t.Fatal("decode official plan")
		}
		if err := os.WriteFile(filepath.Join(output, "plan-"+listed.ID+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		for _, module := range plan.Modules {
			if len(module.Instances) == 0 {
				pending = append(pending, module.TestModule)
			}
			for _, id := range module.Instances {
				data := read("/api/log/export/" + id)
				name := id + ".zip"
				if err := os.WriteFile(filepath.Join(exports, name), data, 0600); err != nil {
					t.Fatal(err)
				}
				archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal("invalid official export")
				}
				for _, member := range archive.File {
					if !strings.HasSuffix(member.Name, ".json") {
						continue
					}
					file, err := member.Open()
					if err != nil {
						t.Fatal(err)
					}
					content, err := io.ReadAll(io.LimitReader(file, 32<<20))
					_ = file.Close()
					if err != nil || len(content) == 32<<20 {
						t.Fatal("read official export")
					}
					sigFile, err := archive.Open(strings.TrimSuffix(member.Name, ".json") + ".sig")
					if err != nil {
						t.Fatal("unsigned official export")
					}
					encoded, err := io.ReadAll(io.LimitReader(sigFile, 16384))
					_ = sigFile.Close()
					if err != nil {
						t.Fatal(err)
					}
					signature, err := base64.URLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
					if err != nil {
						signature, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
					}
					if err != nil {
						t.Fatal("invalid export signature encoding")
					}
					digest := sha256.Sum256(content)
					valid := false
					for _, key := range keys {
						if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil {
							valid = true
							break
						}
					}
					if !valid {
						t.Fatal("invalid official export signature")
					}
					verified++
					var exported struct {
						TestInfo map[string]any   `json:"testInfo"`
						Results  []map[string]any `json:"results"`
					}
					if json.Unmarshal(content, &exported) != nil {
						t.Fatal("decode signed export")
					}
					info := exported.TestInfo
					if info == nil {
						t.Fatal("missing original module outcome")
					}
					result, _ := info["result"].(string)
					if result == "" {
						result = "UNKNOWN"
					}
					outcomes[result]++
					row := map[string]any{"id": id, "name": module.TestModule, "result": result, "status": info["status"], "export": "exports/" + name}
					modules = append(modules, row)
					for i, event := range exported.Results {
						if source, ok := event["page_source"].(string); ok {
							capture := fmt.Sprintf("visual-%s-%d.html.txt", id, i)
							if err := os.WriteFile(filepath.Join(output, capture), []byte(source), 0600); err != nil {
								t.Fatal(err)
							}
							visuals++
						}
					}
				}
			}
		}
	}
	summary := map[string]any{"runner_exit_code": exit, "outcomes": outcomes, "modules": modules, "not_run": pending, "verified_signed_exports": verified, "visual_captures": visuals}
	foundationWriteJSON(t, filepath.Join(output, "summary.json"), summary)
	page := template.Must(template.New("report").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>AuthCrunch OIDC conformance</title><h1>Official OIDC conformance rehearsal</h1><p>Private local library evidence. This does not validate Caddy or confer OpenID certification.</p><p>Original runner exit: {{.runner_exit_code}}. Outcomes: {{.outcomes}}. Verified signed exports: {{.verified_signed_exports}}. Visual captures: {{.visual_captures}}.</p><p>REVIEW requires examination of the captured login or error page. WARNING and SKIPPED remain non-pass outcomes. The original runner result is preserved without exclusions.</p><p><a href="summary.json">Complete summary</a> · <a href="execution.json">Execution</a> · <a href="candidate.json">Candidate</a> · <a href="source-manifest.json">Source hashes</a> · <a href="discovery.json">Discovery</a> · <a href="deployment.redacted.json">Redacted deployment</a> · <a href="suite-jwks.json">Export verification keys</a> · <a href="runner.log">Private runner log</a></p><table><tr><th>Module</th><th>Outcome</th><th>Status</th><th>Evidence</th></tr>{{range .modules}}<tr><td>{{.name}}</td><td>{{.result}}</td><td>{{.status}}</td><td><a href="{{.export}}">Original signed export (includes visual evidence)</a></td></tr>{{end}}</table><p>Not run: {{.not_run}}</p></html>`))
	file, err := os.OpenFile(filepath.Join(output, "index.html"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := page.Execute(file, summary); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("Original official outcomes: %v; runner exit %d; verified exports %d; visual captures %d", outcomes, exit, verified, visuals)
}
