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

package refresh

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testIdentity struct {
	mu     sync.Mutex
	claims map[string]any
	err    error
}

func (i *testIdentity) WithIdentity(ctx context.Context, _ Principal, apply func(map[string]any) error) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.err != nil {
		return i.err
	}
	return apply(i.claims)
}

type testSigner struct {
	sign func(map[string]any) (string, error)
}

func (s *testSigner) Sign(_ context.Context, m map[string]any) (string, error) {
	if s.sign != nil {
		return s.sign(m)
	}
	return "signed-access", nil
}

type testManager struct {
	manager   *Manager
	store     *MemoryStore
	identity  *testIdentity
	signer    *testSigner
	clock     atomic.Int64
	principal Principal
}

func newTestManager(t *testing.T) *testManager {
	t.Helper()
	h := &testManager{identity: &testIdentity{claims: map[string]any{"roles": []string{"user"}, "aud": []string{"app"}, "scopes": []string{"read"}}}, signer: &testSigner{}}
	h.clock.Store(1000)
	h.principal = Principal{Backend: "local", Realm: "local", UserID: "immutable-id", Subject: "alice", AuthTime: 1000, Methods: []string{"pwd"}, Challenges: []string{"password:"}}
	var err error
	h.store, err = NewMemoryStore(10, 100)
	if err != nil {
		t.Fatal(err)
	}
	h.manager, err = NewManager(h.store, h.identity, h.signer, Policy{time.Minute, 5 * time.Minute, time.Hour}, Binding{Portal: "portal", Origin: "https://auth.example.test", BasePath: "/auth"})
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Unix(h.clock.Load(), 0) }
	h.manager.now, h.store.now = now, now
	return h
}
func (h *testManager) issue(t *testing.T) *Result {
	t.Helper()
	r, err := h.manager.Issue(context.Background(), h.principal, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRefreshLifecycle(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	h.clock.Add(61) // The access JWT has expired; refresh remains authenticated.
	h.identity.claims["roles"] = []string{"new-role"}
	h.identity.claims["aud"] = []string{"app", "other-app"}
	h.identity.claims["scopes"] = []string{"read", "write"}
	h.identity.claims["sub"] = "forged-subject"
	h.identity.claims["auth_time"] = int64(2000)
	h.identity.claims["acr"] = "forged-assurance"
	next, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	if next.RefreshToken == first.RefreshToken || next.SessionID != first.SessionID || next.Claims["jti"] == first.Claims["jti"] {
		t.Fatal("rotation did not preserve session and replace credentials")
	}
	if next.Claims["sub"] != "alice" || next.Claims["auth_time"] != int64(1000) || next.AbsoluteExpiresAt != first.AbsoluteExpiresAt {
		t.Fatal("authentication grant changed")
	}
	if _, ok := next.Claims["acr"]; ok {
		t.Fatal("invented assurance survived")
	}
	if got := next.Claims["roles"].([]string); len(got) != 1 || got[0] != "new-role" {
		t.Fatal("stale roles")
	}
	if got := next.Claims["aud"].([]string); len(got) != 1 || got[0] != "app" {
		t.Fatal("audience expanded")
	}
	if got := next.Claims["scopes"].([]string); len(got) != 1 || got[0] != "read" {
		t.Fatal("scope expanded")
	}
	if err := h.manager.Logout(context.Background(), next.RefreshToken, CookieTransport); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Refresh(context.Background(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatalf("logout did not revoke: %v", err)
	}
}

func TestRefreshReplayAndIsolation(t *testing.T) {
	h := newTestManager(t)
	first, unrelated := h.issue(t), h.issue(t)
	next, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("spent credential accepted")
	}
	if _, err := h.manager.Refresh(context.Background(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("replay did not revoke descendant")
	}
	unknown, _, _ := newToken()
	if _, err := h.manager.Refresh(context.Background(), unknown, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown accepted")
	}
	if _, err := h.manager.Refresh(context.Background(), unrelated.RefreshToken, BodyTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("transport switched")
	}
	if _, err := h.manager.Refresh(context.Background(), unrelated.RefreshToken, CookieTransport); err != nil {
		t.Fatal("unrelated family revoked", err)
	}
}

func TestRefreshDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance int64
	}{{"idle", 300}, {"absolute", 3600}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestManager(t)
			first := h.issue(t)
			h.clock.Add(tc.advance)
			if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expired accepted: %v", err)
			}
		})
	}
	t.Run("absolute cap", func(t *testing.T) {
		h := newTestManager(t)
		h.principal.AuthTime = -1
		if _, err := h.manager.Issue(context.Background(), h.principal, CookieTransport); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid auth time accepted")
		}
		h.principal.AuthTime = 1000
		h.clock.Store(4590)
		first := h.issue(t)
		if first.AccessExpiresAt != 4600 || first.RefreshExpiresAt != 4600 {
			t.Fatal("absolute timeout exceeded")
		}
	})
}

func TestRefreshFailuresDoNotSpend(t *testing.T) {
	for _, tc := range []string{"signer", "slow signer", "directory", "cancelled"} {
		t.Run(tc, func(t *testing.T) {
			h := newTestManager(t)
			first := h.issue(t)
			ctx := context.Background()
			switch tc {
			case "signer":
				h.signer.sign = func(map[string]any) (string, error) { return "", errors.New("offline") }
			case "slow signer":
				h.signer.sign = func(map[string]any) (string, error) { h.clock.Add(60); return "staged", nil }
			case "directory":
				h.identity.err = errors.New("offline")
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if result, err := h.manager.Refresh(ctx, first.RefreshToken, CookieTransport); err == nil || result != nil {
				t.Fatal("failed issuance exposed credentials")
			}
			h.signer.sign = nil
			h.identity.err = nil
			if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); err != nil {
				t.Fatal("failure consumed token", err)
			}
		})
	}
}

func TestRefreshIdentityDenialRevokes(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	h.identity.err = ErrDenied
	if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	h.identity.err = nil
	if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("denial did not revoke")
	}
}

func TestRefreshRemovedAudienceRequiresLogin(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	h.identity.claims["aud"] = []string{"different-app"}
	if _, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrDenied) {
		t.Fatalf("removed audience did not deny: %v", err)
	}
}

func TestRefreshConcurrentReuse(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	var wg sync.WaitGroup
	results := make(chan *Result, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport)
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for r := range results {
		if r != nil {
			successes++
			if _, err := h.manager.Refresh(context.Background(), r.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
				t.Fatal("concurrent replay left descendant alive")
			}
		}
	}
	if successes != 1 {
		t.Fatalf("wanted one rotation, got %d", successes)
	}
}

func TestRefreshLogoutDuringSigning(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.signer.sign = func(map[string]any) (string, error) { close(entered); <-release; return "staged", nil }
	done := make(chan error, 1)
	go func() {
		_, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport)
		done <- err
	}()
	<-entered
	if err := h.manager.Logout(context.Background(), first.RefreshToken, CookieTransport); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrInvalid) {
		t.Fatalf("logout race issued a token: %v", err)
	}
}

func TestRefreshStoreBoundsAndBinding(t *testing.T) {
	h := newTestManager(t)
	h.store.capacity = 1
	h.store.maxRotations = 1
	first := h.issue(t)
	if _, err := h.manager.Issue(context.Background(), h.principal, CookieTransport); !errors.Is(err, ErrUnavailable) {
		t.Fatal("capacity not enforced")
	}
	d, _ := digest(first.RefreshToken)
	wrong := h.manager.binding
	wrong.Transport = CookieTransport
	wrong.Portal = "other"
	if _, err := h.store.Lookup(context.Background(), d, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("portal binding ignored")
	}
	next, err := h.manager.Refresh(context.Background(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Refresh(context.Background(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("rotation capacity not enforced")
	}
	h.clock.Store(4600)
	h.principal.AuthTime = 4600
	h.issue(t)
	if len(h.store.tokens) != 1 || len(h.store.families) != 1 {
		t.Fatal("cleanup retained expired digests")
	}
}

func TestRefreshTokenParsing(t *testing.T) {
	token, d, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := digest(token)
	if err != nil || parsed != d {
		t.Fatal("token round trip failed")
	}
	for _, s := range []string{"", "access.jwt.signature", token + "=", token + "x", " " + token, token[:len(token)-1] + "!"} {
		if _, err := digest(s); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}

func FuzzRefreshToken(f *testing.F) {
	token, _, _ := newToken()
	f.Add(token)
	f.Add("access.jwt.signature")
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := digest(s); err == nil && (len(s) != 48 || s[:5] != tokenPrefix) {
			t.Fatal("noncanonical credential")
		}
	})
}
