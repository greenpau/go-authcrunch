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

package tokenrefresh

import (
	"context"
	"errors"
	"testing"
)

func TestRefreshSessionPrecondition(t *testing.T) {
	h := newTestManager(t)
	first, second := h.issue(t), h.issue(t)
	for range 2 {
		id, err := h.manager.GetSessionID(t.Context(), first.RefreshToken, CookieTransport)
		if err != nil || id != first.SessionID {
			t.Fatal("current session lookup failed")
		}
	}
	signed := false
	h.signer.sign = func(map[string]any) (string, error) { signed = true; return "signed-access", nil }
	for _, id := range []string{"", second.SessionID, "unknown-session"} {
		result, err := h.manager.RefreshForSession(t.Context(), first.RefreshToken, CookieTransport, id)
		if result != nil || err == nil || signed {
			t.Fatal("mismatched or empty session reached signing")
		}
	}
	next, err := h.manager.RefreshForSession(t.Context(), first.RefreshToken, CookieTransport, first.SessionID)
	if err != nil || next.SessionID != first.SessionID || !signed {
		t.Fatal("correct precondition did not rotate the original credential")
	}
	if _, err := h.manager.GetSessionID(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("spent lookup bypassed replay checks")
	}
	if _, err := h.manager.RefreshForSession(t.Context(), next.RefreshToken, CookieTransport, first.SessionID); !errors.Is(err, ErrInvalid) {
		t.Fatal("spent lookup left a descendant usable")
	}
	if _, err := h.manager.RefreshForSession(t.Context(), second.RefreshToken, CookieTransport, second.SessionID); err != nil {
		t.Fatal("precondition/replay affected another family")
	}
}

func TestGetSessionIDValidation(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	for _, input := range []struct{ token, transport string }{
		{"malformed", CookieTransport}, {first.RefreshToken, "invalid"}, {first.RefreshToken, BodyTransport},
	} {
		id, err := h.manager.GetSessionID(t.Context(), input.token, input.transport)
		if id != "" || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid lookup exposed an ID")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if id, err := h.manager.GetSessionID(ctx, first.RefreshToken, CookieTransport); id != "" || !errors.Is(err, context.Canceled) {
		t.Fatal("lookup ignored cancellation")
	}
	h.store.Close()
	if id, err := h.manager.GetSessionID(t.Context(), first.RefreshToken, CookieTransport); id != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("lookup ignored store closure")
	}
}

func TestValidateSessionLifecycle(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	for range 2 {
		if err := h.manager.ValidateSession(t.Context(), first.SessionID, CookieTransport); err != nil {
			t.Fatal("live session rejected", err)
		}
	}
	// Liveness is not identity authorization and does not create credentials.
	h.identity.err = ErrDenied
	if err := h.manager.ValidateSession(t.Context(), first.SessionID, CookieTransport); err != nil {
		t.Fatal("liveness unexpectedly authenticated identity", err)
	}
	h.identity.err = nil
	next, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport)
	if err != nil {
		t.Fatal("liveness check consumed a credential", err)
	}
	if err := h.manager.ValidateSession(t.Context(), first.SessionID, CookieTransport); err != nil {
		t.Fatal("healthy rotation invalidated the family reference", err)
	}
	if _, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("liveness changed ordinary replay rejection")
	}
	if err := h.manager.ValidateSession(t.Context(), first.SessionID, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("replay-revoked family remained live")
	}
	if _, err := h.manager.Refresh(t.Context(), next.RefreshToken, CookieTransport); !errors.Is(err, ErrInvalid) {
		t.Fatal("liveness lost spent-token revocation history")
	}
}

func TestValidateSessionBoundaries(t *testing.T) {
	for _, scenario := range []string{"empty", "unknown", "wrong transport", "invalid transport", "wrong origin", "wrong mount", "wrong portal", "logout", "replacement", "idle expiry", "absolute expiry", "closed", "cancelled", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			h := newTestManager(t)
			first := h.issue(t)
			id, transport := first.SessionID, CookieTransport
			ctx := t.Context()
			want := ErrInvalid
			switch scenario {
			case "empty":
				id = ""
			case "unknown":
				id = "unknown"
			case "wrong transport":
				transport = BodyTransport
			case "invalid transport":
				transport = "invalid"
			case "wrong origin":
				h.manager.binding.Origin = "https://other.example.test"
			case "wrong mount":
				h.manager.binding.BasePath = "/other"
			case "wrong portal":
				h.manager.binding.Portal = "other"
			case "logout":
				if err := h.manager.Logout(ctx, first.RefreshToken, CookieTransport); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if _, err := h.manager.IssueReplacing(ctx, h.principal, CookieTransport, []string{first.RefreshToken}); err != nil {
					t.Fatal(err)
				}
			case "idle expiry":
				h.clock.Store(first.RefreshExpiresAt)
			case "absolute expiry":
				h.clock.Store(first.AbsoluteExpiresAt)
			case "closed":
				h.store.Close()
				want = ErrUnavailable
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "unsupported":
				h.manager.store = struct{ Store }{h.store}
				want = ErrUnavailable
			}
			if err := h.manager.ValidateSession(ctx, id, transport); !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}
