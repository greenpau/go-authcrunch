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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/httpserver"
	serverparser "github.com/greenpau/go-authcrunch/pkg/httpserver/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EAuthdb(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "authdb")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildContext, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(buildContext, "go", "build", "-mod=readonly", "-race", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build authdb: %v\n%s", err, output)
	}
	t.Run("commands", func(t *testing.T) {
		for _, tc := range []struct {
			args []string
			fail bool
			want string
		}{
			{nil, false, "COMMANDS:"},
			{[]string{"--help"}, false, "GLOBAL OPTIONS:"},
			{[]string{"-h"}, false, "COMMANDS:"},
			{[]string{"help"}, false, "COMMANDS:"},
			{[]string{"help", "run"}, false, "authdb run"},
			{[]string{"run", "--help"}, false, "--config PATH"},
			{[]string{"run", "-h"}, false, "--debug"},
			{[]string{"--version"}, false, "authdb "},
			{[]string{"-v"}, false, "authdb "},
			{[]string{"version"}, false, "authdb "},
			{[]string{"unknown"}, true, "unknown command"},
			{[]string{"help", "unknown"}, true, "No help topic"},
			{[]string{"run", "--unknown"}, true, "flag provided but not defined"},
			{[]string{"run", "--config"}, true, "flag needs an argument"},
			{[]string{"run", "extra"}, true, "positional arguments"},
			{[]string{"version", "extra"}, true, "positional arguments"},
		} {
			t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				cmd := authdbCommand(ctx, binary, tc.args...)
				cmd.Env = append(cmd.Env, "AUTHDB_CONFIG_PATH="+filepath.Join(t.TempDir(), "absent.json"))
				output, err := cmd.CombinedOutput()
				if (err != nil) != tc.fail || ctx.Err() != nil || !bytes.Contains(output, []byte(tc.want)) {
					t.Fatalf("command failed: %v; output: %s", err, output)
				}
			})
		}
	})
	t.Run("flag placement and precedence", func(t *testing.T) {
		cfg, _ := executableConfig(t, "/auth", true)
		path := writeServerConfig(t, cfg)
		t.Chdir(filepath.Dir(path))
		absent := filepath.Join(t.TempDir(), "absent.json")
		for _, tc := range []struct {
			name        string
			args        []string
			environment string
			debug       bool
		}{
			{"default configuration", []string{"run"}, "", false},
			{"command flags", []string{"run", "--config", path, "--debug"}, absent, true},
			{"global flags", []string{"--config", path, "--debug", "run"}, absent, true},
			{"environment", []string{"run"}, path, false},
			{"command overrides global", []string{"-c", absent, "run", "-c", path}, absent, false},
			{"global debug command config", []string{"--debug", "run", "-c", path}, absent, true},
			{"explicit debug false", []string{"--debug", "-c", path, "run", "--debug=false"}, absent, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var environment []string
				if tc.environment != "" {
					environment = append(environment, "AUTHDB_CONFIG_PATH="+tc.environment)
				}
				process := startAuthdbCommand(t, binary, tc.args, environment)
				client := &http.Client{Timeout: 5 * time.Second}
				defer client.CloseIdleConnections()
				response, _ := serverRequest(t, client, http.MethodGet, "http://"+process.address+"/auth/login", "", nil)
				if response.StatusCode != http.StatusOK {
					t.Fatal("selected configuration did not serve its portal")
				}
				process.stop(t)
				assertAuthdbDebug(t, process, tc.debug)
			})
		}
	})
	t.Run("startup failures", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			pipe := filepath.Join(t.TempDir(), "config.fifo")
			if err := exec.CommandContext(t.Context(), "mkfifo", pipe).Run(); err != nil {
				t.Fatal("create nonregular configuration fixture:", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			output, err := authdbCommand(ctx, binary, "run", "--config", pipe).CombinedOutput()
			cancel()
			if err == nil || !bytes.Contains(output, []byte("regular file")) {
				t.Fatal("nonregular configuration did not fail promptly")
			}
		}
		for _, body := range []string{
			`{"SECRET":"do-not-print"}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/login-service"}]},"security":{"authentication_portals":[{"name":"portal"}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth\u0000"}]},"security":{"authentication_portals":[{"name":"portal"}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"missing","path":"/auth"}]},"security":{}}`,
			`{"http":{"tls_certificate_file":"absent","tls_key_file":"absent","portals":[{"name":"portal","path":"/auth"}]},"security":{"authentication_portals":[{"name":"portal"}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{"authentication_portals":[null]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{"credentials":{"raw_credential_configs":[["SECRET do-not-print extra"]]},"authentication_portals":[{"name":"portal"}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{"authentication_portals":[{"name":"portal","trusted_login_redirect_uri_configs":[null]}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{"authentication_portals":[{"name":"portal","ui":{"static_assets":[null]}}]}}`,
			`{"http":{"insecure_http":true,"portals":[{"name":"portal","path":"/auth"}]},"security":{"authentication_portals":[{"name":"portal","raw_crypto_key_store_config":["crypto"]}]}}`,
		} {
			name := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(name, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			output, err := authdbCommand(ctx, binary, "run", "--config", name).CombinedOutput()
			cancel()
			if err == nil || ctx.Err() == context.DeadlineExceeded {
				t.Fatal("startup error did not exit promptly with failure")
			}
			if bytes.Contains(output, []byte("SECRET")) || bytes.Contains(output, []byte("do-not-print")) || bytes.Contains(output, []byte("panic:")) {
				t.Fatal("startup error leaked data or panicked")
			}
		}
	})
	for _, mount := range []string{"/", "/auth", "/tenant/auth"} {
		t.Run("TLS portal "+mount, func(t *testing.T) {
			cfg, client := executableConfig(t, mount, false)
			var options []string
			if mount == "/auth" {
				options = append(options, "--debug")
			}
			process := startAuthdb(t, binary, cfg, options...)
			origin := "https://" + process.address
			base := origin + strings.TrimSuffix(mount, "/")
			loginResponse, body := serverRequest(t, client, http.MethodGet, base+"/login", "", nil)
			if loginResponse.StatusCode != http.StatusOK || loginResponse.ProtoMajor != 2 || !bytes.Contains(body, []byte("/assets/")) {
				t.Fatalf("login page unavailable over HTTP/2: status %d, protocol %s", loginResponse.StatusCode, loginResponse.Proto)
			}
			for asset, contentType := range map[string]string{"/assets/css/basic.css": "text/css", "/assets/js/login.js": "application/javascript"} {
				response, content := serverRequest(t, client, http.MethodGet, base+asset, "", nil)
				if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), contentType) || len(content) == 0 {
					t.Fatal("browser asset unavailable within portal mount")
				}
			}
			response, _ := serverRequest(t, client, http.MethodGet, origin+mount, "", nil)
			if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != strings.TrimSuffix(mount, "/")+"/login" {
				t.Fatal("portal root did not redirect within mount")
			}
			// Direct clients cannot change the perceived server origin.
			response, _ = serverRequest(t, client, http.MethodGet, base+"/portal", "", http.Header{"X-Forwarded-Host": {"untrusted.example"}, "X-Forwarded-Proto": {"http"}, "X-Forwarded-Prefix": {"/wrong"}})
			if strings.Contains(response.Header.Get("Location"), "untrusted") || strings.Contains(response.Header.Get("Location"), "wrong") {
				t.Fatal("forwarding headers reached the portal")
			}
			auth, err := authclient.NewClient(&authclient.Config{BaseURL: base, Realm: "local", Username: "admin", Password: tests.TestPwd1}, authclient.Options{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			credential, err := auth.Authenticate(t.Context())
			if err != nil {
				t.Fatal("standalone portal login failed:", err)
			}
			authorization, err := credential.Authorization()
			if err != nil {
				t.Fatal("invalid returned credentials")
			}
			response, body = serverRequest(t, client, http.MethodGet, base+"/whoami?format=json", "", http.Header{"Authorization": {authorization}})
			if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("admin")) {
				t.Fatal("issued token did not authenticate whoami")
			}
			response, _ = serverRequest(t, client, http.MethodGet, base+"/whoami?format=json", "", nil)
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatal("anonymous whoami unexpectedly authorized")
			}
			response, body = serverRequest(t, client, http.MethodPost, base+"/api/server/realms", `{"query":"all"}`, http.Header{"Authorization": {authorization}, "Content-Type": {"application/json"}})
			if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"realm":"local"`)) {
				t.Fatal("admin API unavailable")
			}
			response, _ = serverRequest(t, client, http.MethodPost, base+"/api/server/realms", `{"query":"all"}`, http.Header{"Content-Type": {"application/json"}})
			if response.StatusCode == http.StatusOK {
				t.Fatal("admin API authorized an anonymous request")
			}
			for _, target := range []string{"/outside", strings.TrimSuffix(mount, "/") + "extra/login"} {
				if mount != "/" {
					response, _ = serverRequest(t, client, http.MethodGet, origin+target, "", nil)
					if response.StatusCode != http.StatusNotFound {
						t.Fatal("portal route crossed its boundary")
					}
				}
			}
			wrong, err := authclient.NewClient(&authclient.Config{BaseURL: base, Realm: "local", Username: "admin", Password: "incorrect-password"}, authclient.Options{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrong.Authenticate(t.Context()); err == nil {
				t.Fatal("incorrect password accepted")
			}
			// A second process must fail when binding the active listener.
			cfg.HTTP.ListenAddress = process.address
			duplicate := writeServerConfig(t, cfg)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			output, err := authdbCommand(ctx, binary, "run", "--config", duplicate).CombinedOutput()
			cancel()
			if err == nil || !bytes.Contains(output, []byte("listen:")) {
				t.Fatal("occupied listener did not fail")
			}
			process.stop(t)
			assertAuthdbDebug(t, process, mount == "/auth")
			logs, err := os.ReadFile(process.logPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(logs, []byte(tests.TestPwd1)) || bytes.Contains(logs, []byte(credential.AccessToken)) {
				t.Fatal("server logged credentials")
			}
			// The identity file survives a restart and remains usable.
			cfg.HTTP.ListenAddress = "127.0.0.1:0"
			replacement := startAuthdb(t, binary, cfg)
			client.CloseIdleConnections()
			auth, err = authclient.NewClient(&authclient.Config{BaseURL: "https://" + replacement.address + strings.TrimSuffix(mount, "/"), Realm: "local", Username: "admin", Password: tests.TestPwd1}, authclient.Options{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auth.Authenticate(t.Context()); err != nil {
				t.Fatal("persisted identity login failed after restart")
			}
			replacement.stop(t)
		})
	}
	if runtime.GOOS != "windows" {
		t.Run("second signal interrupts drain", func(t *testing.T) {
			cfg, _ := executableConfig(t, "/auth", true)
			cfg.HTTP.ReadHeaderTimeout = "30s"
			cfg.HTTP.ShutdownTimeout = "20s"
			process := startAuthdb(t, binary, cfg)
			connection, err := net.DialTimeout("tcp", process.address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if _, err := io.WriteString(connection, "GET /auth/login HTTP/1.1\r\nHost: localhost\r\n"); err != nil {
				t.Fatal(err)
			}
			// An incomplete request keeps graceful shutdown draining while a
			// completed request establishes that the accept loop is running.
			client := &http.Client{Timeout: time.Second}
			defer client.CloseIdleConnections()
			serverRequest(t, client, http.MethodGet, "http://"+process.address+"/auth/login", "", nil)
			if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				probe, err := net.DialTimeout("tcp", process.address, 100*time.Millisecond)
				if err != nil {
					break
				}
				probe.Close()
				if time.Now().After(deadline) {
					t.Fatal("first signal did not stop listening")
				}
				time.Sleep(10 * time.Millisecond)
			}
			select {
			case <-process.done:
				process.stopped = true
				t.Fatal("server exited before the second signal")
			default:
			}
			if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-process.done:
				process.stopped = true
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatal("second signal did not interrupt the graceful drain")
				}
				status, ok := exitErr.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
					t.Fatal("server failed instead of terminating on the second signal")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("second signal was swallowed during graceful shutdown")
			}
		})
	}
	t.Run("explicit HTTP and multiple portals", func(t *testing.T) {
		cfg, _ := executableConfig(t, "/auth", true)
		cfg.HTTP.Portals = append(cfg.HTTP.Portals, httpserver.PortalRoute{Name: "second", Path: "/second"})
		cfg.Security.AuthenticationPortals = append(cfg.Security.AuthenticationPortals, &authn.PortalConfig{Name: "second", IdentityStores: []string{"local"}})
		process := startAuthdb(t, binary, cfg)
		client := &http.Client{Timeout: 10 * time.Second}
		defer client.CloseIdleConnections()
		for _, mount := range []string{"/auth", "/second"} {
			response, _ := serverRequest(t, client, http.MethodGet, "http://"+process.address+mount+"/login", "", nil)
			if response.StatusCode != http.StatusOK {
				t.Fatal("HTTP portal unavailable")
			}
		}
		process.stop(t)
	})
}

func executableConfig(t *testing.T, mount string, insecure bool) (*configuration, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "admin", Email: "admin@example.test", Password: tests.TestPwd1, Roles: []string{"authp/admin", "authp/user"}}}); err != nil {
		t.Fatal("provision identity:", err)
	}
	// Use the standard library's fixture certificate and trust it explicitly.
	fixture := httptest.NewUnstartedServer(http.NotFoundHandler())
	fixture.EnableHTTP2 = true
	fixture.StartTLS()
	certificate := fixture.TLS.Certificates[0]
	client := fixture.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fixture.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS12
	t.Cleanup(client.CloseIdleConnections)
	statements := []string{"listen 127.0.0.1:0", cfgutil.EncodeArgs([]string{"portal", "portal", mount}), "timeout read header 5s", "timeout read 10s", "timeout write 15s", "timeout idle 20s", "timeout shutdown 3s", "max header bytes 4096"}
	if insecure {
		statements = append(statements, "insecure http enabled")
	} else {
		statements = append(statements, cfgutil.EncodeArgs([]string{"tls", "certificate", certPath}), cfgutil.EncodeArgs([]string{"tls", "key", keyPath}))
	}
	transport, err := serverparser.NewHTTPServerConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	return &configuration{HTTP: transport, Security: &authcrunch.Config{
		IdentityStores:        []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
		AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, API: &authn.APIConfig{AdminEnabled: true}}},
	}}, client
}

func writeServerConfig(t *testing.T, cfg *configuration) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("serialize config:", err)
	}
	name := filepath.Join(t.TempDir(), "authdb.json")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

type authdbProcess struct {
	cmd              *exec.Cmd
	done             chan error
	address, logPath string
	stopped          bool
}

func authdbCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "AUTHDB_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	return cmd
}

func assertAuthdbDebug(t *testing.T, process *authdbProcess, want bool) {
	t.Helper()
	data, err := os.ReadFile(process.logPath)
	if err != nil {
		t.Fatal(err)
	}
	debug := false
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var record struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal("server did not emit structured JSON logs")
		}
		debug = debug || record.Level == "debug"
	}
	if debug != want {
		t.Fatalf("debug logs present: %v, want %v", debug, want)
	}
}

func startAuthdb(t *testing.T, binary string, cfg *configuration, options ...string) *authdbProcess {
	t.Helper()
	args := append([]string{"run", "--config", writeServerConfig(t, cfg)}, options...)
	return startAuthdbCommand(t, binary, args, nil)
}

func startAuthdbCommand(t *testing.T, binary string, args, environment []string) *authdbProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	process := &authdbProcess{cmd: authdbCommand(ctx, binary, args...), done: make(chan error, 1), logPath: filepath.Join(t.TempDir(), "server.log")}
	process.cmd.Env = append(process.cmd.Env, environment...)
	log, err := os.OpenFile(process.logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	process.cmd.Stdout, process.cmd.Stderr = log, log
	if err := process.cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	go func() { err := process.cmd.Wait(); log.Close(); process.done <- err }()
	t.Cleanup(func() { process.stop(t) })
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case err := <-process.done:
			process.stopped = true
			t.Fatal("server exited before readiness:", err)
		case <-deadline.C:
			t.Fatal("server readiness timed out")
		case <-ticker.C:
			data, err := os.ReadFile(process.logPath)
			if err != nil {
				t.Fatal(err)
			}
			for line := range strings.SplitSeq(string(data), "\n") {
				var record struct {
					Message string `json:"msg"`
					Address string `json:"address"`
				}
				if json.Unmarshal([]byte(line), &record) == nil && record.Message == "authdb listening" {
					process.address = record.Address
					return process
				}
			}
		}
	}
}

func (p *authdbProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	if runtime.GOOS == "windows" {
		_ = p.cmd.Process.Kill()
	} else {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case err := <-p.done:
		if err != nil && runtime.GOOS != "windows" {
			if data, readErr := os.ReadFile(p.logPath); readErr == nil {
				if start := bytes.Index(data, []byte("WARNING: DATA RACE")); start >= 0 {
					end := bytes.Index(data[start:], []byte("=================="))
					if end > 0 {
						t.Log(string(data[start : start+end]))
					}
				}
			}
			t.Errorf("server did not shut down cleanly: %v", err)
		}
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("server failed to stop within deadline")
	}
}

func serverRequest(t *testing.T, client *http.Client, method, target, body string, headers http.Header) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		request.Header = headers
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}
