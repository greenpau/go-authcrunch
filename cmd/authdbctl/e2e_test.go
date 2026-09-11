// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const cliE2ESecret = "0123456789abcdef0123456789abcdef"
const cliE2EAPIKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"

// Build the actual executable once. Every invocation has its own process and
// home, and uses production CLI parsing, filesystem IO, HTTP and exit behavior.
func TestE2EAuthdbctl(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "authdbctl")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-race", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authdbctl: %v\n%s", err, output)
	}
	for _, method := range []string{"password", "totp", "api key", "piped identity"} {
		t.Run("connect "+method, func(t *testing.T) {
			f := newCLIE2EPortal(t, method, false)
			home := t.TempDir()
			cfg := f.config()
			input := ""
			if method == "piped identity" {
				cfg.Username, cfg.Realm = "", ""
				input = tests.TestUser1 + "\nlocal\n"
			}
			writeE2EConfig(t, home, cfg)
			out, diagnostic, err := runCLIProcess(t, binary, home, input, nil, "connect")
			if err != nil {
				t.Fatalf("connect exited unsuccessfully: %v", err)
			}
			if strings.Contains(out+diagnostic, tests.TestPwd1) || strings.Contains(out+diagnostic, cliE2EAPIKey) || strings.Contains(out+diagnostic, cliE2ESecret) {
				t.Fatal("connect output leaked configured credentials")
			}
			want := 2
			if method == "totp" {
				want = 3
			}
			if method == "api key" {
				want = 1
			}
			f.assertOnlyLogin(t, want)
			path := filepath.Join(home, ".config", "authdbctl", "token.jwt")
			f.assertCredential(t, path)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if method != "piped identity" {
				if method == "api key" {
					cfg.APIKey = strings.Repeat("Z", 64)
				} else {
					cfg.Password = "incorrect-test-password"
				}
				writeE2EConfig(t, home, cfg)
				if _, _, err := runCLIProcess(t, binary, home, "", nil, "connect"); err == nil {
					t.Fatal("invalid credentials exited successfully")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(original, after) {
					t.Fatal("failed login replaced the previous credential file")
				}
			}
		})
	}
	for _, method := range []string{"password", "totp", "mfa", "invalid MFA", "unsupported WebAuthn"} {
		t.Run("interactive "+method, func(t *testing.T) {
			factor := method
			if method == "invalid MFA" || method == "unsupported WebAuthn" {
				factor = "mfa"
			}
			f := newCLIE2EPortal(t, factor, false)
			home := t.TempDir()
			cfg := f.config()
			cfg.Password, cfg.TOTPSecret = "", ""
			writeE2EConfig(t, home, cfg)
			answers := []terminalAnswer{{"Please enter password: ", func() string { return tests.TestPwd1 }}}
			switch method {
			case "mfa":
				answers = append(answers, terminalAnswer{"Enter 1 for MFA Application token OR enter 2 for U2F/WebAuthn: ", func() string { return "1" }})
			case "invalid MFA":
				answers = append(answers, terminalAnswer{"Enter 1 for MFA Application token OR enter 2 for U2F/WebAuthn: ", func() string { return "3" }})
			case "unsupported WebAuthn":
				answers = append(answers, terminalAnswer{"Enter 1 for MFA Application token OR enter 2 for U2F/WebAuthn: ", func() string { return "2" }})
			}
			if method == "totp" || method == "mfa" {
				answers = append(answers, terminalAnswer{"Please enter authenticator app code: ", cliTOTP})
			}
			err := runInteractiveCLI(t, binary, home, answers, "connect")
			path := filepath.Join(home, ".config", "authdbctl", "token.jwt")
			if method == "invalid MFA" || method == "unsupported WebAuthn" {
				if err == nil {
					t.Fatal("unsupported interactive authentication exited successfully")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("failed interactive login persisted credentials")
				}
				want := 2
				if method == "unsupported WebAuthn" {
					want = 3
				}
				f.assertOnlyLogin(t, want)
				return
			}
			if err != nil {
				t.Fatalf("interactive connect failed: %v", err)
			}
			want := 2
			if method != "password" {
				want = 3
			}
			f.assertOnlyLogin(t, want)
			f.assertCredential(t, path)
		})
	}

	t.Run("management lifecycle and cached authentication", func(t *testing.T) {
		f := newCLIE2EPortal(t, "password", true)
		home := t.TempDir()
		writeE2EConfig(t, home, f.config())
		run := func(args ...string) map[string]any {
			t.Helper()
			out, _, err := runCLIProcess(t, binary, home, "", nil, args...)
			if err != nil {
				t.Fatalf("command %s failed: %v", args[0], err)
			}
			var data map[string]any
			if err := json.Unmarshal([]byte(out), &data); err != nil || data == nil {
				t.Fatal("command did not emit a JSON object")
			}
			if data["status"] == "failure" {
				t.Fatal("command reported a failed operation with exit status zero")
			}
			return data
		}
		run("metadata") // No cache: login and execute in one command.
		loginCount := f.loginCount()
		if loginCount != 2 {
			t.Fatalf("initial command used %d login requests", loginCount)
		}
		run("list", "realms")
		run("info", "realm", "--realm", "local")
		if _, _, err := runCLIProcess(t, binary, home, "", nil, "info", "realm", "--realm", "missing-realm"); err == nil {
			t.Fatal("unknown realm exited successfully")
		}
		created := run("add", "user", "--realm", "local", "--username", "jdoe", "--email", "jdoe@example.test", "--name", "Jane Doe", "--roles", "authp/user")
		password, ok := created["password"].(string)
		if !ok || f.persistedUser(t, "jdoe").VerifyPassword(password) != nil {
			t.Fatal("created user's returned password does not authenticate")
		}
		identityArgs := []string{"user", "--realm", "local", "--username", "jdoe", "--email", "jdoe@example.test"}
		run(append([]string{"info"}, identityArgs...)...)
		run(append(append([]string{"update"}, identityArgs...), "--overwrite-roles", "viewer")...)
		run(append(append([]string{"update"}, identityArgs...), "--add-roles", "editor")...)
		roles := f.persistedUser(t, "jdoe").GetRolesClaim()
		if !slices.Contains(roles, "viewer") || !slices.Contains(roles, "editor") {
			t.Fatal("role changes were not persisted")
		}
		run(append(append([]string{"update"}, identityArgs...), "--disable")...)
		if !f.persistedUser(t, "jdoe").Disabled {
			t.Fatal("disable was not persisted")
		}
		run(append(append([]string{"update"}, identityArgs...), "--enable")...)
		if f.persistedUser(t, "jdoe").Disabled {
			t.Fatal("enable was not persisted")
		}
		reset := run(append(append([]string{"update"}, identityArgs...), "--reset-password")...)
		newPassword, ok := reset["password"].(string)
		if !ok || newPassword == password || f.persistedUser(t, "jdoe").VerifyPassword(newPassword) != nil {
			t.Fatal("reset password was not usable")
		}
		run(append(append([]string{"update"}, identityArgs...), "--overwrite-auth-challenges", "password")...)
		run("reload", "--realm", "local")
		run("list", "users", "--realm", "local")
		run(append([]string{"delete"}, identityArgs...)...)
		if f.persistedUser(t, "jdoe") != nil {
			t.Fatal("delete was not persisted")
		}
		if _, _, err := runCLIProcess(t, binary, home, "", nil, append([]string{"delete"}, identityArgs...)...); err == nil {
			t.Fatal("failed server operation exited successfully")
		}
		if f.loginCount() != loginCount {
			t.Fatal("management commands failed to reuse cached credentials")
		}
		path := filepath.Join(home, ".config", "authdbctl", "token.jwt")
		store, err := authclient.NewFileTokenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(&authclient.Credentials{AccessToken: "invalid-cached-token"}); err != nil {
			t.Fatal(err)
		}
		run("--retries", "2", "--retry-interval", "0s", "metadata")
		if f.loginCount() != loginCount+2 {
			t.Fatal("invalid cached token did not cause exactly one fresh login")
		}
		f.assertCredential(t, path)
	})
	t.Run("flag and environment routing", func(t *testing.T) {
		f := newCLIE2EPortal(t, "api key", false)
		home := t.TempDir()
		configHome := t.TempDir()
		configPath := writeE2EConfig(t, configHome, f.config())
		token := filepath.Join(home, "custom", "token.jwt")
		env := []string{"AUTHDBCTL_CONFIG_PATH=" + configPath, "AUTHDBCTL_TOKEN_PATH=" + token}
		if _, _, err := runCLIProcess(t, binary, home, "", env, "connect"); err != nil {
			t.Fatal("environment-selected configuration failed")
		}
		f.assertCredential(t, token)
		env[0] = "AUTHDBCTL_CONFIG_PATH=" + filepath.Join(home, "missing")
		if _, _, err := runCLIProcess(t, binary, home, "", env, "--config", configPath, "connect"); err != nil {
			t.Fatal("explicit config flag did not override environment")
		}
		for _, args := range [][]string{{"--help"}, {"--version"}} {
			out, _, err := runCLIProcess(t, binary, home, "", nil, args...)
			if err != nil || !strings.Contains(out, "authdbctl") {
				t.Fatal("help or version failed")
			}
		}
		before := f.loginCount()
		if _, _, err := runCLIProcess(t, binary, home, "", env, "add", "user"); err == nil {
			t.Fatal("missing required flags exited successfully")
		}
		if f.loginCount() != before {
			t.Fatal("invalid command reached the portal")
		}
	})
}

func cliProcessEnv(home string, extra []string) []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "HOME" || name == "USERPROFILE" || strings.HasPrefix(name, "AUTHDBCTL_") || name == "GORACE" || name == "GOCOVERDIR" {
			continue
		}
		env = append(env, entry)
	}
	return append(append(env, "HOME="+home, "USERPROFILE="+home, "GORACE=halt_on_error=1 atexit_sleep_ms=0"), extra...)
}

func runCLIProcess(t *testing.T, binary, home, input string, env []string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = home, cliProcessEnv(home, env)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("CLI process did not finish before the deadline")
	}
	return stdout.String(), stderr.String(), err
}

func writeE2EConfig(t *testing.T, home string, cfg Config) string {
	t.Helper()
	path := filepath.Join(home, ".config", "authdbctl", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type cliE2EPortal struct {
	server         *httptest.Server
	dbPath, method string
	mu             sync.Mutex
	routes         []string
}

func newCLIE2EPortal(t *testing.T, method string, admin bool) *cliE2EPortal {
	t.Helper()
	f := &cliE2EPortal{dbPath: filepath.Join(t.TempDir(), "users.json"), method: method}
	db, err := identity.NewDatabase(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{"authp/user"}
	if admin {
		roles = append(roles, "authp/admin")
	}
	req := &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1, Roles: roles}}
	if err := db.AddUser(req); err != nil {
		t.Fatal(err)
	}
	if method == "totp" || method == "mfa" {
		req.MfaToken = requests.MfaToken{Type: "totp", Comment: "CLI E2E factor", Secret: cliE2ESecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
		if err := db.AddMfaToken(req); err != nil {
			t.Fatal(err)
		}
	}
	if method == "mfa" {
		req.User.Challenges = []string{"password mfa"}
		if err := db.OverwriteUserAuthChallengeRules(req); err != nil {
			t.Fatal(err)
		}
	}

	if method == "api key" {
		req.Key = requests.Key{Payload: cliE2EAPIKey, Usage: "api", Comment: "CLI E2E key"}
		if err := db.AddAPIKey(req); err != nil {
			t.Fatal(err)
		}
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "localdb", Kind: "local", Params: map[string]any{"path": f.dbPath, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	cookies := cookie.NewConfig()
	cookies.Insecure = true // The standalone CLI connects only to a loopback HTTP listener.
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "cli-e2e", IdentityStores: []string{"localdb"}, CookieConfig: cookies, API: &authn.APIConfig{AdminEnabled: admin}}, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.routes = append(f.routes, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("real portal handler failed")
		}
	}))
	t.Cleanup(func() { f.server.Close(); portal.Close() })
	return f
}

func (f *cliE2EPortal) config() Config {
	cfg := Config{Config: authclient.Config{BaseURL: f.server.URL + "/auth", Username: tests.TestUser1, Realm: "local", Password: tests.TestPwd1}}
	if f.method == "totp" {
		cfg.TOTPSecret = cliE2ESecret
	}
	if f.method == "api key" {
		cfg.Username, cfg.Password, cfg.APIKey = "", "", cliE2EAPIKey
	}
	return cfg
}

func (f *cliE2EPortal) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, route := range f.routes {
		if route == "POST /auth/login" {
			count++
		}
	}
	return count
}

func (f *cliE2EPortal) assertOnlyLogin(t *testing.T, count int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.routes) != count {
		t.Fatalf("got %d login requests, want %d", len(f.routes), count)
	}
	for _, route := range f.routes {
		if route != "POST /auth/login" {
			t.Fatal("connect accessed a route other than login")
		}
	}
}

func (f *cliE2EPortal) assertCredential(t *testing.T, path string) {
	t.Helper()
	store, err := authclient.NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	header, err := credentials.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("credential file permissions are not private")
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/auth/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", header)
	resp, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var claims map[string]any
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&claims) != nil || claims["sub"] != tests.TestUser1 {
		t.Fatal("persisted CLI credential does not authorize its expected identity")
	}
}

func (f *cliE2EPortal) persistedUser(t *testing.T, name string) *identity.User {
	t.Helper()
	db, err := identity.NewDatabase(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range db.Users {
		if u.Username == name {
			return u
		}
	}
	return nil
}

type terminalAnswer struct {
	prompt string
	value  func() string
}

func runInteractiveCLI(t *testing.T, binary, home string, answers []terminalAnswer, args ...string) error {
	t.Helper()
	terminal := newTerminalFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = home, cliProcessEnv(home, nil)
	cmd.Stdin = terminal.file
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	output := bufio.NewReader(stdout)
	var transcript strings.Builder
	var secrets []string
	for _, answer := range answers {
		var prompt strings.Builder
		for !strings.HasSuffix(prompt.String(), answer.prompt) {
			ch, err := output.ReadByte()
			if err != nil {
				t.Fatal("CLI stopped before its expected authentication prompt")
			}
			prompt.WriteByte(ch)
		}
		transcript.WriteString(prompt.String())
		value := answer.value() // Generate a fresh TOTP only when it is requested.
		if len(value) > 3 {
			secrets = append(secrets, value)
		}
		terminal.send(t, value)
		terminal.expect(t, "sent")
	}
	rest, readErr := io.ReadAll(output)
	transcript.Write(rest)
	err = cmd.Wait()
	if readErr != nil {
		t.Fatal("failed to collect CLI output")
	}
	if ctx.Err() != nil {
		t.Fatal("interactive CLI timed out")
	}
	terminal.assertRestored(t)
	for _, secret := range secrets {
		if strings.Contains(transcript.String()+diagnostic.String(), secret) {
			t.Fatal("interactive CLI disclosed hidden input")
		}
	}
	return err
}

func cliTOTP() string {
	mac := hmac.New(sha1.New, []byte(cliE2ESecret))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
