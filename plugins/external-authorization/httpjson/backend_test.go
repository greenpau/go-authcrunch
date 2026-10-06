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

package httpjson_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
)

func decisionRequest() external.Request {
	return external.Request{Policy: "reports", Version: "v1", Identity: external.Identity{Issuer: "issuer", Realm: "realm", Subject: "alice", Tenant: "north"}, Action: "GET", Resource: "/reports", Attributes: map[string]any{"custom": map[string]any{"number": json.Number("9007199254740993"), "null": nil}}}
}

const granted = `{"decision":"allow","policy":"reports","version":"v1"}`

func TestHTTPJSONResponseContract(t *testing.T) {
	cases := []struct {
		name, body, media string
		status            int
		chunked           bool
		compressed        bool
		want              bool
		large             bool
	}{
		{name: "allow", body: granted, want: true},
		{name: "deny", body: `{"decision":"deny","policy":"reports","version":"v1"}`, want: true},
		{name: "charset", body: granted, media: "application/json; charset=utf-8", want: true},
		{name: "exact limit", body: granted + strings.Repeat(" ", 4096-len(granted)), want: true},
		{name: "compressed allow", body: granted, compressed: true, want: true},
		{name: "empty"}, {name: "null", body: `null`}, {name: "missing", body: `{}`},
		{name: "boolean", body: `{"decision":true,"policy":"reports","version":"v1"}`},
		{name: "unknown decision", body: strings.Replace(granted, "allow", "abstain", 1)},
		{name: "duplicate", body: `{"decision":"deny","decision":"allow","policy":"reports","version":"v1"}`},
		{name: "case alias", body: `{"Decision":"allow","policy":"reports","version":"v1"}`},
		{name: "unknown field", body: strings.TrimSuffix(granted, "}") + `,"obligations":[]}`},
		{name: "wrong policy", body: strings.Replace(granted, "reports", "other", 1)},
		{name: "wrong version", body: strings.Replace(granted, "v1", "v2", 1)},
		{name: "extra object", body: granted + granted}, {name: "array", body: "[" + granted + "]"},
		{name: "invalid JSON", body: `{"decision":`}, {name: "invalid utf8", body: strings.TrimSuffix(granted, "}") + ",\"other\":\"\xff\"}"},
		{name: "text", body: granted, media: "text/plain"}, {name: "failure status", body: granted, status: 503},
		{name: "empty status", body: granted, status: 204}, {name: "redirect", body: granted, status: 302},
		{name: "large declared", body: strings.Repeat(" ", 4097), large: true},
		{name: "large chunked", body: strings.Repeat(" ", 4097), chunked: true, large: true},
		{name: "large decompressed", body: granted + strings.Repeat(" ", 4096), compressed: true, large: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("invalid decision transport")
				}
				var input external.Request
				decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
				decoder.UseNumber()
				if decoder.Decode(&input) != nil || input.Identity.Subject != "alice" || input.Attributes["custom"].(map[string]any)["number"] != json.Number("9007199254740993") {
					t.Error("request shape or precision changed")
				}
				media := tc.media
				if media == "" {
					media = "application/json"
				}
				w.Header().Set("Content-Type", media)
				status := tc.status
				if status == 0 {
					status = 200
				}
				if tc.compressed {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if tc.large && !tc.chunked && !tc.compressed {
					w.Header().Set("Content-Length", fmt.Sprint(len(tc.body)))
				}
				w.WriteHeader(status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				var output io.Writer = w
				if tc.compressed {
					writer := gzip.NewWriter(w)
					defer writer.Close()
					output = writer
				}
				_, _ = io.WriteString(output, tc.body)
			}))
			defer srv.Close()
			cfg := &httpjson.Config{Endpoint: srv.URL}
			backend, err := httpjson.New(cfg, srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			cfg.Endpoint = "https://changed.invalid"
			result, err := backend.Decide(t.Context(), decisionRequest())
			if (err == nil) != tc.want || !tc.want && result != nil {
				t.Fatalf("accepted=%t, want %t", err == nil, tc.want)
			}
			if tc.large && !errors.Is(err, httpjson.ErrResponseTooLarge) {
				t.Fatal("missing size sentinel")
			}
			if err != nil && (strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), tc.body) && tc.body != "") {
				t.Fatal("failure disclosed endpoint or response")
			}
		})
	}
}

func TestHTTPJSONConfigAndLifecycle(t *testing.T) {
	for _, endpoint := range []string{"https://policy.test/decide", "http://127.0.0.1:80/decide", "http://[::1]/decide"} {
		cfg := &httpjson.Config{Endpoint: endpoint}
		if err := cfg.Validate(); err != nil || cfg.Timeout != "1s" {
			t.Fatal("valid endpoint rejected")
		}
	}
	for _, endpoint := range []string{"", "/relative", "http://policy.test", "http://localhost", "ftp://127.0.0.1", "https://user:secret@policy.test", "https://policy.test?secret=x", "https://policy.test#secret", "https://policy.test#", "https://policy.test:0", "https://policy.test:65536", "https://policy.test:", "https://policy.test?", "https://policy.test/\nsecret", "https://policy.test/\xff", "https://%"} {
		cfg := &httpjson.Config{Endpoint: endpoint}
		if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("bad endpoint accepted or disclosed")
		}
	}
	for _, duration := range []string{"0s", "-1s", "31s", "invalid"} {
		if (&httpjson.Config{Endpoint: "https://policy.test", Timeout: duration}).Validate() == nil {
			t.Fatal("invalid timeout accepted")
		}
	}
	if (*httpjson.Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
	if b, err := httpjson.New(nil, nil); b != nil || err == nil {
		t.Fatal("nil constructor accepted")
	}
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, granted)
	}))
	defer srv.Close()
	backend, err := httpjson.New(&httpjson.Config{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := backend.Decide(t.Context(), decisionRequest()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 8 {
		t.Fatal("unexpected caching or retries")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r, err := backend.Decide(ctx, decisionRequest()); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	backend.Close()
	backend.Close()
	if r, err := backend.Decide(t.Context(), decisionRequest()); r != nil || err == nil {
		t.Fatal("closed backend allowed request")
	}
	var noContext context.Context
	if r, err := (*httpjson.Backend)(nil).Decide(noContext, external.Request{}); r != nil || err == nil {
		t.Fatal("nil backend accepted")
	}
	(*httpjson.Backend)(nil).Close()
	if calls.Load() != 8 {
		t.Fatal("canceled or closed request reached service")
	}
}

func TestHTTPJSONRedirectCookiesAndTimeout(t *testing.T) {
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Error("ambient cookie sent")
		}
		http.Redirect(w, r, target.URL, 307)
	}))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(srv.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "secret", Value: "canary"}})
	client := srv.Client()
	client.Jar = jar
	backend, err := httpjson.New(&httpjson.Config{Endpoint: srv.URL}, client)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if result, err := backend.Decide(t.Context(), decisionRequest()); result != nil || err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() != 0 || client.Jar != jar || client.CheckRedirect != nil {
		t.Fatal("redirect followed or caller mutated")
	}
	started, canceled := make(chan struct{}), make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 64<<10))
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer slow.Close()
	backend2, err := httpjson.New(&httpjson.Config{Endpoint: slow.URL, Timeout: "50ms"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer backend2.Close()
	if result, err := backend2.Decide(t.Context(), decisionRequest()); result != nil || err == nil {
		t.Fatal("timeout allowed")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout fixture not called")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("outbound context not canceled")
	}
	// Ordinary connection failure yields no private transport diagnostic or grant.
	slow.Close()
	if result, err := backend2.Decide(t.Context(), decisionRequest()); result != nil || !errors.Is(err, external.ErrUnavailable) || strings.Contains(err.Error(), slow.URL) {
		t.Fatal("outage accepted or disclosed")
	}
}

func TestHTTPJSONBodyCancellation(t *testing.T) {
	headers := make(chan struct{})
	canceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 64<<10))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":`)
		w.(http.Flusher).Flush()
		close(headers)
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
			t.Error("body cancellation did not reach server")
		}
		close(canceled)
	}))
	defer srv.Close()
	backend, err := httpjson.New(&httpjson.Config{Endpoint: srv.URL, Timeout: "2s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := backend.Decide(ctx, decisionRequest())
		if result != nil {
			t.Error("partial response granted a decision")
		}
		done <- err
	}()
	select {
	case <-headers:
	case <-time.After(time.Second):
		t.Fatal("headers not received")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("body cancellation cause lost")
		}
	case <-time.After(time.Second):
		t.Fatal("body read did not cancel")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request not canceled")
	}
}
