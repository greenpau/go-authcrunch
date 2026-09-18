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

package authn

import (
	"encoding/base64"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestPasswordAttemptKeys(t *testing.T) {
	tests := []struct {
		name, address, source, block string
	}{
		{name: "public IPv4", address: "203.0.113.27", source: "203.0.113.27", block: "203.0.113.0/24"},
		{name: "public IPv4 port", address: "203.0.113.28:8443", source: "203.0.113.28", block: "203.0.113.0/24"},
		{name: "RFC1918 10", address: "10.20.30.40", source: "10.20.30.40", block: "10.20.30.40/32"},
		{name: "RFC1918 172", address: "172.31.30.40", source: "172.31.30.40", block: "172.31.30.40/32"},
		{name: "RFC1918 192", address: "192.168.30.40", source: "192.168.30.40", block: "192.168.30.40/32"},
		{name: "IPv6", address: "[2001:db8::1]:443", source: "2001:db8::1", block: "2001:db8::1/128"},
		{name: "mapped RFC1918", address: "::ffff:192.168.1.7", source: "192.168.1.7", block: "192.168.1.7/32"},
		{name: "invalid", address: "not-an-address", source: unknownPasswordSource, block: unknownPasswordSource},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, block := passwordAttemptKeys(tc.address)
			if source != tc.source || block != tc.block {
				t.Fatalf("passwordAttemptKeys(%q) = (%q, %q), want (%q, %q)", tc.address, source, block, tc.source, tc.block)
			}
		})
	}
}

func TestPasswordAttemptLimiterSourceAndNetworkBlocks(t *testing.T) {
	now := time.Date(2026, 9, 17, 18, 0, 0, 0, time.UTC)
	limiter := newPasswordAttemptLimiter(func() time.Time { return now }, 32)

	for range passwordAttemptLimit - 1 {
		failPasswordAttempt(t, limiter, "203.0.113.10")
		failPasswordAttempt(t, limiter, "203.0.113.20")
	}
	if attempt, err := limiter.begin("203.0.113.30"); err != nil {
		t.Fatal("failures from other addresses prematurely blocked the public subnet")
	} else if !attempt.finish(true) {
		t.Fatal("successful unblocked attempt was denied")
	}

	failPasswordAttempt(t, limiter, "203.0.113.10")
	if _, err := limiter.begin("203.0.113.200"); err != errPasswordAttemptLimited {
		t.Fatalf("public /24 remained available after one source reached the limit: %v", err)
	}
	if attempt, err := limiter.begin("203.0.114.10"); err != nil {
		t.Fatalf("unrelated public subnet was blocked: %v", err)
	} else if !attempt.finish(true) {
		t.Fatal("unrelated public subnet could not finish")
	}

	for range passwordAttemptLimit {
		failPasswordAttempt(t, limiter, "192.168.1.10")
	}
	if attempt, err := limiter.begin("192.168.1.11"); err != nil {
		t.Fatalf("RFC1918 block spread beyond its /32: %v", err)
	} else if !attempt.finish(true) {
		t.Fatal("neighboring RFC1918 address could not finish")
	}

	now = now.Add(passwordAttemptBlockDuration)
	if attempt, err := limiter.begin("203.0.113.10"); err != nil {
		t.Fatalf("expired public block remained active: %v", err)
	} else if !attempt.finish(true) {
		t.Fatal("attempt after public block expiry could not finish")
	}
}

func TestPasswordAttemptLimiterConcurrentReservations(t *testing.T) {
	limiter := newPasswordAttemptLimiter(time.Now, 32)
	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			<-start
			attempt, err := limiter.begin("198.51.100.17")
			if err != nil {
				results <- false
				return
			}
			attempt.finish(false)
			results <- true
		})
	}
	close(start)
	wg.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != passwordAttemptLimit {
		t.Fatalf("concurrent limiter allowed %d attempts, want %d", allowed, passwordAttemptLimit)
	}
}

func TestPasswordAttemptLimiterSuccessResetsSourceFailures(t *testing.T) {
	limiter := newPasswordAttemptLimiter(time.Now, 32)
	for range passwordAttemptLimit - 1 {
		failPasswordAttempt(t, limiter, "198.51.100.10")
	}
	attempt, err := limiter.begin("198.51.100.10")
	if err != nil || !attempt.finish(true) {
		t.Fatal("successful fifth attempt was denied")
	}
	for range passwordAttemptLimit - 1 {
		failPasswordAttempt(t, limiter, "198.51.100.10")
	}
	if attempt, err := limiter.begin("198.51.100.200"); err != nil {
		t.Fatal("successful login did not reset the exact source failure counter")
	} else {
		attempt.finish(true)
	}
}

func TestPasswordAttemptLimiterConcurrentBlockDeniesSuccess(t *testing.T) {
	limiter := newPasswordAttemptLimiter(time.Now, 32)
	success, err := limiter.begin("192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	for range passwordAttemptLimit {
		failPasswordAttempt(t, limiter, "192.0.2.10")
	}
	if success.finish(true) {
		t.Fatal("in-flight success survived a concurrent public subnet block")
	}
}

func TestPasswordAttemptLimiterCapacityAndClose(t *testing.T) {
	now := time.Date(2026, 9, 17, 18, 0, 0, 0, time.UTC)
	limiter := newPasswordAttemptLimiter(func() time.Time { return now }, 1)
	failPasswordAttempt(t, limiter, "203.0.113.1")
	if _, err := limiter.begin("203.0.114.1"); err != errPasswordAttemptLimited {
		t.Fatalf("full limiter did not fail closed: %v", err)
	}
	now = now.Add(passwordAttemptBlockDuration)
	attempt, err := limiter.begin("203.0.114.1")
	if err != nil {
		t.Fatalf("expired entry retained capacity: %v", err)
	}
	limiter.close()
	if attempt.finish(true) {
		t.Fatal("attempt completed after limiter close")
	}
	if _, err := limiter.begin("203.0.114.1"); err != errPasswordAttemptLimited {
		t.Fatalf("closed limiter accepted an attempt: %v", err)
	}
}

func TestPasswordAttemptLimiterAuthProxyBasicAuth(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"},
	}}); err != nil {
		t.Fatal(err)
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{
		Name: "password-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	portal, err := NewPortal(PortalParameters{
		Config: &PortalConfig{Name: "password-attempt-basic-auth", IdentityStores: []string{"password-local"}, RawCryptoKeyStoreConfig: []string{"crypto default autogenerate tag password-attempt-test"}},
		Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(portal.Close)
	for _, payload := range []string{"alice", "alice:", ":password"} {
		request := &authproxy.Request{Realm: "local", Address: "198.51.100.10", Secret: base64.StdEncoding.EncodeToString([]byte(payload))}
		if err := portal.BasicAuth(request); err != autherrors.ErrBasicAuthFailedDecodeSecret || request.Response.Payload != "" {
			t.Fatalf("malformed custom BasicAuth payload %q returned %v or a credential", payload, err)
		}
	}

	wrong := base64.StdEncoding.EncodeToString([]byte("alice:wrong-password"))
	for range passwordAttemptLimit {
		if err := portal.BasicAuth(&authproxy.Request{Realm: "local", Address: "198.51.100.10", Secret: wrong}); err == nil {
			t.Fatal("wrong custom BasicAuth password succeeded")
		}
	}
	correct := base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1))
	blocked := &authproxy.Request{Realm: "local", Address: "198.51.100.200", Secret: correct}
	if err := portal.BasicAuth(blocked); err == nil || blocked.Response.Payload != "" {
		t.Fatal("blocked custom BasicAuth request returned a credential")
	}
	allowed := &authproxy.Request{Realm: "local", Address: "198.51.101.10", Secret: correct}
	if err := portal.BasicAuth(allowed); err != nil || allowed.Response.Payload == "" {
		t.Fatal("unrelated custom BasicAuth source could not authenticate")
	}
}

func TestParseBasicAuthHeaderRejectsMissingSeparator(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://portal.example.test/basic/login/local", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice")))
	if _, err := parseBasicAuthHeader(request); err == nil {
		t.Fatal("Basic Authorization without a username/password separator was accepted")
	}
}

func failPasswordAttempt(t *testing.T, limiter *passwordAttemptLimiter, source string) {
	t.Helper()
	attempt, err := limiter.begin(source)
	if err != nil {
		t.Fatalf("begin failed password attempt from %s: %v", source, err)
	}
	attempt.finish(false)
}
