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

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func lifecycleOAuthConfig(url string) *Config {
	return &Config{Name: "shutdown", Realm: "test", Driver: "generic", ClientID: "client", ClientSecret: "synthetic", BaseAuthURL: url, MetadataURL: url + "/metadata", TLSInsecureSkipVerify: true}
}

func awaitOAuthLifecycle(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not complete", operation)
	}
}

func TestOAuthShutdownCancelsSetup(t *testing.T) {
	for _, stage := range []string{"metadata", "keys"} {
		for _, delayed := range []bool{false, true} {
			name := stage
			if delayed {
				name += "/delayed"
			}
			t.Run(name, func(t *testing.T) {
				entered, canceled := make(chan struct{}), make(chan struct{})
				abort := make(chan struct{})
				var srv *httptest.Server
				srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if stage == "keys" && r.URL.Path == "/metadata" {
						_ = json.NewEncoder(w).Encode(map[string]any{"authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys"})
						return
					}
					close(entered)
					select {
					case <-r.Context().Done():
					case <-abort:
					}
					close(canceled)
				}))
				defer srv.Close()
				defer close(abort)
				cfg := lifecycleOAuthConfig(srv.URL)
				if delayed {
					cfg.DelayStart = 1
				}
				b, err := NewIdentityProvider(cfg, zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				configured := make(chan error, 1)
				go func() { configured <- b.Configure() }()
				awaitOAuthLifecycle(t, entered, "setup request")
				closed := make(chan struct{})
				go func() { b.Close(); close(closed) }()
				awaitOAuthLifecycle(t, closed, "provider shutdown")
				awaitOAuthLifecycle(t, canceled, "network cancellation")
				select {
				case err := <-configured:
					if !delayed && err == nil {
						t.Fatal("interrupted synchronous setup succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("Configure survived Close")
				}
				if b.Configured() || b.ready.Load() {
					t.Fatal("disposed provider remained ready")
				}
				if err := b.Configure(); err == nil {
					t.Fatal("closed provider restarted")
				}
				if err := b.Authenticate(&requests.Request{}); err == nil {
					t.Fatal("closed provider authenticated")
				}
				select {
				case <-b.stateDone:
				default:
					t.Fatal("state worker survived Close")
				}
			})
		}
	}
}

func TestOAuthShutdownAwaitsRetry(t *testing.T) {
	retry, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var attempts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	core, _ := observer.New(zap.DebugLevel)
	logger := zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "fetchMetadataURL failed" {
			close(retry)
			<-release
		}
		return nil
	}))
	cfg := lifecycleOAuthConfig(srv.URL)
	cfg.RetryAttempts = 3
	cfg.RetryInterval = 3600
	b, err := NewIdentityProvider(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { releaseOnce.Do(func() { close(release) }); b.Close() }()
	configured := make(chan error, 1)
	go func() { configured <- b.Configure() }()
	awaitOAuthLifecycle(t, retry, "first failed attempt")
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	// Cancellation signals before waiting for the registered setup goroutine.
	awaitOAuthLifecycle(t, b.stop, "shutdown cancellation")
	select {
	case <-closed:
		t.Fatal("Close returned while owned setup was blocked")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	awaitOAuthLifecycle(t, closed, "retry cancellation")
	if err := <-configured; err == nil {
		t.Fatal("canceled setup succeeded")
	}
	if attempts.Load() != 1 {
		t.Fatal("closed provider retried discovery")
	}
	if b.ready.Load() {
		t.Fatal("closed provider published readiness")
	}
}

func TestOAuthShutdownBeforeConfigureAndDelay(t *testing.T) {
	cfg := lifecycleOAuthConfig("https://idp.example.test")
	cfg.DelayStart = 3600
	b, err := NewIdentityProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Configure(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	awaitOAuthLifecycle(t, done, "initial delay cancellation")
	if b.ready.Load() || b.Configured() {
		t.Fatal("delayed disposed provider became ready")
	}
	if !errors.Is(b.discoveryContext().Err(), context.Canceled) {
		t.Fatal("setup context remained live")
	}
	c, err := NewIdentityProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := c.Configure(); err == nil {
		t.Fatal("Configure after Close succeeded")
	}
	if _, err := NewIdentityProvider(nil, zap.NewNop()); err == nil {
		t.Fatal("nil configuration accepted")
	}
}
