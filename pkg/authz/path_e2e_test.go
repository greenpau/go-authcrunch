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

package authz_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type pathServer struct {
	server     *httptest.Server
	protoMajor int
}

type downstreamHeaders struct {
	Values map[string][]string `json:"values"`
}

func newPathServer(t *testing.T, cfg *authz.PolicyConfig, application http.Handler) *pathServer {
	t.Helper()
	return newPathServerWithProtocol(t, cfg, application, false)
}

func newPathServerWithProtocol(t *testing.T, cfg *authz.PolicyConfig, application http.Handler, http2 bool) *pathServer {
	t.Helper()
	cfg.Name = "path-regression"
	cfg.AuthURLPath = "/login"
	cfg.AuthRedirectDisabled = true
	cfg.ValidateBearerHeader = true
	cfg.RawCryptoKeyStoreConfig = []string{"crypto key verify " + testutils.GetSharedKey()}
	if len(cfg.AccessListRules) == 0 {
		cfg.AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}
	}
	gate, err := authz.NewGatekeeper(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	fixture := &pathServer{protoMajor: 1}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originalPath, originalRawPath, originalURI := r.URL.Path, r.URL.RawPath, r.RequestURI
		ar := requests.NewAuthorizationRequest()
		err := gate.Authenticate(w, r, ar)
		if err != nil || !(ar.Response.Bypassed || ar.Response.Authorized) {
			if err == autherrors.ErrNoTokenFound {
				http.Error(w, "authentication required", http.StatusUnauthorized)
			}
			return
		}
		if r.URL.Path != originalPath || r.URL.RawPath != originalRawPath || (!cfg.StripTokenEnabled && r.RequestURI != originalURI) {
			http.Error(w, "request path was rewritten", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Test-Bypassed", fmt.Sprint(ar.Response.Bypassed))
		w.Header().Set("X-Test-Authorized", fmt.Sprint(ar.Response.Authorized))
		w.Header().Set("X-Test-Application", "reached")
		application.ServeHTTP(w, r)
	}))
	fixture.server.EnableHTTP2 = http2
	if http2 {
		fixture.protoMajor = 2
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	return fixture
}

// Model independent application/proxy normalization rather than importing the
// authorization helper. Some backends clean between decoding passes.
func pathApplication(decodePasses int, cleanFirst bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Path
		for range decodePasses {
			if cleanFirst {
				target = path.Clean(target)
			}
			decoded, err := url.PathUnescape(target)
			if err != nil || decoded == target {
				break
			}
			target = decoded
		}
		target = path.Clean(target)
		if strings.HasPrefix(target, "/admin") {
			_, _ = io.WriteString(w, "private admin fixture")
			return
		}
		_, _ = fmt.Fprintf(w, "application path: %s", target)
	})
}

func (s *pathServer) request(t *testing.T, target, token string, wantStatus int, wantBypass, wantAuthorized bool) {
	t.Helper()
	client := s.server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.server.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != s.protoMajor {
		t.Fatalf("negotiated HTTP/%d, want HTTP/%d", resp.ProtoMajor, s.protoMajor)
	}
	bypassed := resp.Header.Get("X-Test-Bypassed") == "true"
	authorized := resp.Header.Get("X-Test-Authorized") == "true"
	reached := resp.Header.Get("X-Test-Application") == "reached"
	if resp.StatusCode != wantStatus || bypassed != wantBypass || authorized != wantAuthorized || reached != (wantBypass || wantAuthorized) {
		t.Fatalf("status=%d bypass=%t authorized=%t reached=%t; want %d/%t/%t; Path=%q RawPath=%q target=%q", resp.StatusCode, bypassed, authorized, reached, wantStatus, wantBypass, wantAuthorized, req.URL.Path, req.URL.RawPath, target)
	}
	if strings.Contains(string(body), "private admin fixture") {
		t.Fatal("request reached protected downstream content")
	}
}

func (s *pathServer) requestHeaders(t *testing.T, target, token string, headers http.Header) downstreamHeaders {
	t.Helper()
	client := s.server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.server.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		t.Fatalf("status=%d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	var got downstreamHeaders
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func headerApplication(names ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := downstreamHeaders{Values: make(map[string][]string)}
		for _, name := range names {
			if values, exists := r.Header[http.CanonicalHeaderKey(name)]; exists {
				got.Values[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})
}

func TestE2EAuthorizationClaimHeaderBoundary(t *testing.T) {
	const (
		attackerValue = "attacker-controlled"
		verifiedEmail = "verified@example.com"
	)
	newToken := func(t *testing.T, email string) string {
		t.Helper()
		claims := map[string]any{
			"sub":   "header-user",
			"roles": []string{"viewer"},
			"exp":   time.Now().Add(5 * time.Minute).Unix(),
			"iat":   time.Now().Unix(),
		}
		if email != "" {
			claims["email"] = email
		}
		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		usr, err := user.NewUser(data)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := testutils.NewTestCryptoKeyStore()
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.SignToken("access_token", "HS512", usr); err != nil {
			t.Fatal(err)
		}
		return usr.Token
	}

	t.Run("default headers are authoritative for uncached and cached users", func(t *testing.T) {
		names := []string{
			"X-Token-User-Name",
			"X-Token-User-Email",
			"X-Token-User-Roles",
			"X-Token-Subject",
			"X-Client-Context",
		}
		s := newPathServer(t, &authz.PolicyConfig{PassClaimsWithHeaders: true}, headerApplication(names...))
		token := newToken(t, "")
		input := http.Header{
			"X-Token-User-Name":  {attackerValue},
			"X-Token-User-Email": {attackerValue},
			"X-Token-User-Roles": {attackerValue},
			"X-Token-Subject":    {attackerValue},
			"X-Client-Context":   {"preserved"},
		}
		want := map[string][]string{
			"X-Token-User-Roles": {"viewer"},
			"X-Token-Subject":    {"header-user"},
			"X-Client-Context":   {"preserved"},
		}
		for round := range 2 {
			got := s.requestHeaders(t, "/private", token, input)
			if diff := cmp.Diff(want, got.Values); diff != "" {
				t.Fatalf("round %d downstream headers mismatch (-want +got):\n%s", round, diff)
			}
		}
	})

	t.Run("mixed case custom headers and collisions are authoritative", func(t *testing.T) {
		names := []string{"X-Custom-Department", "X-Token-User-Email", "X-Verified-Email", "X-Unowned-Claim"}
		cfg := &authz.PolicyConfig{
			PassClaimsWithHeaders: true,
			HeaderInjectionConfigs: []*injector.Config{
				{Header: "x-cUsToM-DePaRtMeNt", Field: "metadata.department"},
				{Header: "x-ToKeN-uSeR-eMaIl", Field: "metadata.department"},
				{Header: "x-vErIfIeD-eMaIl", Field: "email"},
			},
		}
		s := newPathServer(t, cfg, headerApplication(names...))
		token := newToken(t, verifiedEmail)
		input := http.Header{
			"X-Custom-Department": {attackerValue},
			"X-Token-User-Email":  {attackerValue},
			"X-Verified-Email":    {attackerValue},
			"X-Unowned-Claim":     {"preserved"},
		}
		want := map[string][]string{
			"X-Verified-Email": {verifiedEmail},
			"X-Unowned-Claim":  {"preserved"},
		}
		for round := range 2 {
			got := s.requestHeaders(t, "/private", token, input)
			if diff := cmp.Diff(want, got.Values); diff != "" {
				t.Fatalf("round %d downstream headers mismatch (-want +got):\n%s", round, diff)
			}
		}
	})

	t.Run("bypass strips gatekeeper owned headers", func(t *testing.T) {
		names := []string{"X-Token-User-Email", "X-Custom-Department", "X-Unowned-Claim"}
		cfg := &authz.PolicyConfig{
			PassClaimsWithHeaders: true,
			BypassConfigs:         []*bypass.Config{{MatchType: "prefix", URI: "/public/"}},
			HeaderInjectionConfigs: []*injector.Config{
				{Header: "X-Custom-Department", Field: "metadata.department"},
			},
		}
		s := newPathServer(t, cfg, headerApplication(names...))
		input := http.Header{
			"X-Token-User-Email":  {attackerValue},
			"X-Custom-Department": {attackerValue},
			"X-Unowned-Claim":     {"application-value"},
		}
		got := s.requestHeaders(t, "/public/file", "", input)
		if diff := cmp.Diff(map[string][]string{
			"X-Unowned-Claim": {"application-value"},
		}, got.Values); diff != "" {
			t.Fatalf("bypassed downstream headers mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestE2EAuthorizationBypassPaths(t *testing.T) {
	for _, decodePasses := range []int{0, 1, 2, 6} {
		t.Run(fmt.Sprintf("downstream_decodes_%d", decodePasses), func(t *testing.T) {
			s := newPathServer(t, &authz.PolicyConfig{BypassConfigs: []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}}, pathApplication(decodePasses, false))
			for _, target := range []string{
				"/public/", "/public/assets/app.css", "/public/./assets/app.css",
				"/public/%2541+file", "/public/assets%252f", "/public/file?q=%25zz",
				"/public/%25zz", "/public/100%25",
			} {
				t.Run("allow_"+target, func(t *testing.T) { s.request(t, target, "", http.StatusOK, true, false) })
			}
			for _, target := range []string{
				"/admin", "/admin/../public/file", "/admin/%2e%2e/public/file", "/public/a%252fb/../%252e%252e/admin", "/public/..%2f..%2fadmin", "/public/%252e%252e/admin", "/public/..%252fadmin",
				"/public/%25252e%25252e/admin", "/private/%252e%252e/public/file",
				"/public/%252e%252e/admin/%25252e%25252e/public/file",
				"/public/%25zz/%252e%252e/admin",
				"/public/%25252525252e%25252525252e/admin",
			} {
				t.Run("deny_"+target, func(t *testing.T) { s.request(t, target, "", http.StatusUnauthorized, false, false) })
			}
		})
	}
}

func TestE2EAuthorizationRejectsBackslashPathAmbiguity(t *testing.T) {
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := path.Clean(strings.ReplaceAll(r.URL.Path, `\`, "/"))
		if strings.HasPrefix(target, "/admin") {
			_, _ = io.WriteString(w, "private admin fixture")
			return
		}
		_, _ = io.WriteString(w, "public fixture")
	})
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &authz.PolicyConfig{}
			token := ""
			status := http.StatusUnauthorized
			switch mode {
			case "bypass":
				cfg.BypassConfigs = []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}
			case "method":
				cfg.ValidateMethodPath = true
				cfg.AccessListRules = []*acl.RuleConfiguration{
					{Conditions: []string{"prefix match path /admin"}, Action: "deny stop"},
					{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
				}
				token = newPathToken(t, []string{"/public/**"})
				status = http.StatusForbidden
			case "claim":
				cfg.ValidateAccessListPathClaim = true
				token = newPathToken(t, []string{"/public/**"})
				status = http.StatusForbidden
			}
			s := newPathServer(t, cfg, application)
			for _, target := range []string{`/public/\../admin`, "/public/%5c../admin", "/public/%255c../admin"} {
				s.request(t, target, token, status, false, false)
			}
		})
	}
}

func TestE2EAuthorizationPathValidation(t *testing.T) {
	keys, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	usr, err := user.NewUser(fmt.Sprintf(`{
        "sub":"path-viewer", "exp":%d, "iat":%d, "roles":["viewer"], "addr":"127.0.0.1",
        "acl":{"paths":{"/public/**":{},"/public/%%zz":{},"/public/100%%":{},"/public/%%2e%%2e/admin/%%252e%%252e/public/file":{},"/public/a%%2fb/../%%2e%%2e/admin":{},"/public/%%2e%%2e/admin":{}}}
    }`, time.Now().Add(5*time.Minute).Unix(), time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatal("cannot sign fixture token")
	}
	for _, tc := range []struct {
		name                   string
		method, claim, address bool
	}{
		{"method", true, false, false}, {"claim", false, true, false},
		{"method_and_address", true, false, true}, {"claim_and_address", false, true, true},
		{"method_and_claim", true, true, false}, {"method_claim_address", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}
			if tc.method {
				rules = append([]*acl.RuleConfiguration{{Conditions: []string{"prefix match path /admin"}, Action: "deny stop"}}, rules...)
			}
			s := newPathServer(t, &authz.PolicyConfig{ValidateMethodPath: tc.method, ValidateAccessListPathClaim: tc.claim, ValidateSourceAddress: tc.address, AccessListRules: rules}, pathApplication(1, true))
			// Denials in the first round use an uncached identity. The successful
			// requests then populate the cache before the second round.
			for round := range 2 {
				t.Run(fmt.Sprintf("round_%d", round), func(t *testing.T) {
					for _, target := range []string{
						"/admin", "/admin/../public/file", "/admin/%2e%2e/public/file", "/public/a%252fb/../%252e%252e/admin", "/public/%252e%252e/admin", "/public/..%252fadmin",
						"/public/%25zz/%252e%252e/admin",
						"/public/%25252525252e%25252525252e/admin",
						"/public/%252e%252e/admin/%25252e%25252e/public/file",
					} {
						t.Run(target, func(t *testing.T) { s.request(t, target, usr.Token, http.StatusForbidden, false, false) })
					}
					s.request(t, "/public/assets/app.css", usr.Token, http.StatusOK, false, true)
					s.request(t, "/public/%2e/assets/app.css", usr.Token, http.StatusOK, false, true)
					s.request(t, "/public/%25zz", usr.Token, http.StatusOK, false, true)
					s.request(t, "/public/100%25", usr.Token, http.StatusOK, false, true)
				})
			}
		})
	}
}

// ServeMux retains encoded dot segments while routing. A decoded, cleaned copy
// would authorize /public/file while the actual request reaches /admin/.
func TestE2EAuthorizationPathServeMux(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &authz.PolicyConfig{}
			token := ""
			status, bypassed, authorized := http.StatusUnauthorized, true, false
			switch mode {
			case "bypass":
				cfg.BypassConfigs = []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}
			case "method":
				cfg.ValidateMethodPath = true
				cfg.AccessListRules = []*acl.RuleConfiguration{
					{Conditions: []string{"prefix match path /admin"}, Action: "deny stop"},
					{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
				}
			case "claim":
				cfg.ValidateAccessListPathClaim = true
			}
			if mode != "bypass" {
				token = newPathToken(t, []string{"/public/**"})
				status, bypassed, authorized = http.StatusForbidden, false, true
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/admin/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "private admin fixture") })
			mux.HandleFunc("/public/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "public fixture") })
			s := newPathServer(t, cfg, mux)
			for range 2 {
				s.request(t, "/admin/%2e%2e/public/file", token, status, false, false)
				s.request(t, "/public/file", token, http.StatusOK, bypassed, authorized)
			}
		})
	}
}

func newPathToken(t *testing.T, paths []string) string {
	t.Helper()
	keys, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"sub": "path-viewer", "roles": []string{"viewer"},
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
		"acl": map[string]any{"paths": paths},
	})
	if err != nil {
		t.Fatal(err)
	}
	usr, err := user.NewUser(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatal("cannot sign fixture token")
	}
	return usr.Token
}

func TestE2EAuthorizationPathClaimLiterals(t *testing.T) {
	s := newPathServer(t, &authz.PolicyConfig{ValidateAccessListPathClaim: true}, pathApplication(0, false))
	for _, tc := range []struct{ pattern, allowed, denied string }{
		{"/tenant.v1/**", "/tenant.v1/file", "/tenantXv1/file"},
		{"/public/**|/admin", "/public/file%7C/admin", "/admin"},
		{"/public/(admin)/*", "/public/(admin)/file", "/public/admin/file"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			token := newPathToken(t, []string{tc.pattern})
			for range 2 {
				s.request(t, tc.denied, token, http.StatusForbidden, false, false)
				s.request(t, tc.allowed, token, http.StatusOK, false, true)
			}
		})
	}
}

func TestE2EAuthorizationPathClaimsConcurrent(t *testing.T) {
	s := newPathServer(t, &authz.PolicyConfig{ValidateAccessListPathClaim: true}, pathApplication(0, false))
	// One client/transport is safe for concurrent requests once configured.
	client := s.server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	tokens := make([]string, 16)
	for i := range tokens {
		tokens[i] = newPathToken(t, []string{fmt.Sprintf("/tenant.%d/**", i)})
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, token := range tokens {
		wg.Go(func() {
			<-start
			for range 3 {
				for _, tc := range []struct {
					target string
					status int
				}{
					{fmt.Sprintf("/tenant.%d/file", i), http.StatusOK},
					{fmt.Sprintf("/tenantX%d/file", i), http.StatusForbidden},
				} {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.server.URL+tc.target, nil)
					if err != nil {
						t.Error(err)
						return
					}
					req.Header.Set("Authorization", "Bearer "+token)
					resp, err := client.Do(req)
					if err != nil {
						t.Error(err)
						return
					}
					_, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Error(err)
						return
					}
					reached := resp.Header.Get("X-Test-Application") == "reached"
					if resp.StatusCode != tc.status || reached != (tc.status == http.StatusOK) {
						t.Errorf("%s: status=%d reached=%t; want status=%d", tc.target, resp.StatusCode, reached, tc.status)
					}
				}
			}
		})
	}
	close(start)
	wg.Wait()
}

func TestE2EAuthorizationPathNormalizationOrder(t *testing.T) {
	s := newPathServer(t, &authz.PolicyConfig{BypassConfigs: []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}}, pathApplication(1, true))
	s.request(t, "/public/file", "", http.StatusOK, true, false)
	s.request(t, "/public/a%252fb/../%252e%252e/admin", "", http.StatusUnauthorized, false, false)
}

func TestE2EAuthorizationAuthorityForm(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &authz.PolicyConfig{}
			token := ""
			want := http.StatusUnauthorized
			switch mode {
			case "bypass":
				cfg.BypassConfigs = []*bypass.Config{{MatchType: "exact", URI: "/"}}
			case "method":
				cfg.ValidateMethodPath = true
				cfg.AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"match path /"}, Action: "allow stop"}}
			case "claim":
				cfg.ValidateAccessListPathClaim = true
			}
			if mode != "bypass" {
				token = newPathToken(t, []string{"/"})
				want = http.StatusForbidden
			}
			s := newPathServer(t, cfg, pathApplication(0, false))
			client := s.server.Client()
			client.Timeout = 5 * time.Second
			for range 2 {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, s.server.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != want || resp.Header.Get("X-Test-Application") != "" {
					t.Fatalf("authority-form CONNECT received status %d, want %d", resp.StatusCode, want)
				}
				s.request(t, "/", token, http.StatusOK, mode == "bypass", mode != "bypass")
			}
		})
	}
}

// Send the request target verbatim so client URL serialization cannot hide an
// absolute-form or leading-double-slash discrepancy from the server parser.
func TestE2EAuthorizationBypassRequestTargets(t *testing.T) {
	s := newPathServer(t, &authz.PolicyConfig{BypassConfigs: []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}}, pathApplication(1, true))
	roots := x509.NewCertPool()
	roots.AddCert(s.server.Certificate())
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots}}
	for _, tc := range []struct {
		target string
		status int
	}{
		{"http://example.com/public/file?return=%2fadmin", http.StatusOK},
		{"http://example.com/admin/%2e%2e/public/file", http.StatusUnauthorized},
		{"http://example.com/public/a%252fb/../%252e%252e/admin", http.StatusUnauthorized},
		{"//admin/%2e%2e/public/file", http.StatusUnauthorized},
		{"/public//assets/", http.StatusOK},
		{"/publicity/file", http.StatusUnauthorized},
	} {
		t.Run(tc.target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", s.server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", tc.target); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			if err != nil {
				t.Fatal(err)
			}
			reached := resp.Header.Get("X-Test-Application") == "reached"
			if resp.StatusCode != tc.status || reached != (tc.status == http.StatusOK) || strings.Contains(string(body), "private admin fixture") {
				t.Fatalf("status=%d reached=%t, want %d", resp.StatusCode, reached, tc.status)
			}
		})
	}
}

func TestE2EAuthorizationEscapedRouting(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &authz.PolicyConfig{}
			token := ""
			want := http.StatusUnauthorized
			switch mode {
			case "bypass":
				cfg.BypassConfigs = []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}
			case "method":
				cfg.ValidateMethodPath = true
				cfg.AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"prefix match path /public/"}, Action: "allow stop"}}
			case "claim":
				cfg.ValidateAccessListPathClaim = true
			}
			if mode != "bypass" {
				token = newPathToken(t, []string{"/public/**"})
				want = http.StatusForbidden
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/public/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "public fixture") })
			mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "private admin fixture") })
			s := newPathServer(t, cfg, mux)
			for range 2 {
				s.request(t, "/public%2Fadmin", token, want, false, false)
				s.request(t, "/public/file", token, http.StatusOK, mode == "bypass", mode != "bypass")
			}
		})
	}
}

func TestE2EAuthorizationEscapedCleaning(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &authz.PolicyConfig{}
			token := ""
			want := http.StatusUnauthorized
			switch mode {
			case "bypass":
				cfg.BypassConfigs = []*bypass.Config{{MatchType: "regex", URI: `^/public/(admin/\./\.\./file|file)$`}}
			case "method":
				cfg.ValidateMethodPath = true
				cfg.AccessListRules = []*acl.RuleConfiguration{
					{Conditions: []string{"match path /public/admin/file"}, Action: "deny stop"},
					{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
				}
			case "claim":
				cfg.ValidateAccessListPathClaim = true
			}
			if mode != "bypass" {
				token = newPathToken(t, []string{"/public/file", "/public/admin/./../file"})
				want = http.StatusForbidden
			}
			s := newPathServer(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target, err := url.PathUnescape(path.Clean(r.URL.EscapedPath()))
				if err != nil {
					http.Error(w, "bad path", http.StatusBadRequest)
					return
				}
				if target == "/public/admin/file" {
					_, _ = io.WriteString(w, "private admin fixture")
					return
				}
				_, _ = io.WriteString(w, "public fixture")
			}))
			for range 2 {
				s.request(t, "/public/admin/%2e/../file", token, want, false, false)
				s.request(t, "/public/file", token, http.StatusOK, mode == "bypass", mode != "bypass")
			}
		})
	}
}

func TestE2EAuthorizationPathUTF8(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			for _, mode := range []string{"bypass", "method", "claim"} {
				t.Run(mode, func(t *testing.T) {
					cfg := &authz.PolicyConfig{}
					token := ""
					want := http.StatusUnauthorized
					switch mode {
					case "bypass":
						cfg.BypassConfigs = []*bypass.Config{{MatchType: "regex", URI: "^/public/\uFFFD/"}}
					case "method":
						cfg.ValidateMethodPath = true
						cfg.AccessListRules = []*acl.RuleConfiguration{{Conditions: []string{"regex match path ^/public/\uFFFD/"}, Action: "allow stop"}}
					case "claim":
						cfg.ValidateAccessListPathClaim = true
					}
					if mode != "bypass" {
						token = newPathToken(t, []string{"/public/\uFFFD/**"})
						want = http.StatusForbidden
					}
					// ServeMux compares the actual decoded segment bytes. An invalid
					// byte does not name the public U+FFFD directory, even though a
					// regexp matcher may treat both as the replacement character.
					mux := http.NewServeMux()
					mux.HandleFunc("/public/\uFFFD/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "public fixture") })
					mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "private admin fixture") })
					s := newPathServerWithProtocol(t, cfg, mux, http2)
					for range 2 {
						s.request(t, "/public/%FF/file", token, want, false, false)
						s.request(t, "/public/%80/file", token, want, false, false)
						s.request(t, "/public/%EF%BF%BD/file", token, http.StatusOK, mode == "bypass", mode != "bypass")
					}
				})
			}
		})
	}
}
