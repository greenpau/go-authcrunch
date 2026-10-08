// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/openapi"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	adminparser "github.com/greenpau/go-authcrunch/pkg/authn/admin_api/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.uber.org/zap"
)

type openAPIResponseValidator func(*testing.T, string, string, int, http.Header, []byte)

func TestE2EOpenAPIContract(t *testing.T) {
	validate, validateComponent := openAPIContractValidators(t)
	t.Run("login_profile", func(t *testing.T) { testOpenAPILoginAndProfile(t, validate, validateComponent) })
	t.Run("administration", func(t *testing.T) { testOpenAPIAdminContracts(t, validate) })
	t.Run("private_export", func(t *testing.T) { testOpenAPIPrivateExport(t, validate) })
	t.Run("registration", func(t *testing.T) { testOpenAPIRegistration(t, validate) })
	t.Run("generic", func(t *testing.T) { testOpenAPIGenericContracts(t, validate, validateComponent) })
	t.Run("credentials", func(t *testing.T) { testOpenAPICredentials(t, validate, validateComponent) })
	t.Run("provider_route", func(t *testing.T) {
		f := newOpenAPIPortalFixture(t, "/auth", "", false)
		for _, tc := range []struct {
			method string
			status int
		}{{"GET", 400}, {"POST", 405}} {
			h, b := f.request(t, tc.method, "/provider/missing", "", "", tc.status)
			validate(t, "/provider/{realm}", "GET", tc.status, h, b)
			if h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
				t.Fatal("provider response headers changed")
			}
		}
	})
	t.Run("browser", func(t *testing.T) { testOpenAPIBrowserContracts(t, validate) })
	for _, mount := range []string{"/auth", "/team/auth", ""} {
		t.Run("mount="+mount, func(t *testing.T) {
			f := newOpenAPIPortalFixture(t, mount, "enable admin api", true)
			token := f.login(t, "keymember")
			for _, endpoint := range []string{"/.well-known/jwks.json", "/whoami"} {
				h, b := f.request(t, "GET", endpoint, token, "", 200)
				validate(t, endpoint, "GET", 200, h, b)
			}
		})
	}
}

// All credentials come from real password/browser flows across a verified TLS
// listener. Only local account provisioning uses library APIs.
type openAPIPortalFixture struct {
	client      *http.Client
	server      *httptest.Server
	portal      *authn.Portal
	database    string
	key         *ecdsa.PrivateKey
	base, mount string
	secrets     []string
}

func newOpenAPIPortalFixture(t *testing.T, mount, directives string, profile bool) *openAPIPortalFixture {
	return newOpenAPIPortalFixtureWithConfig(t, mount, directives, profile, nil)
}
func newOpenAPIPortalFixtureWithConfig(t *testing.T, mount, directives string, profile bool, configure func(*authn.PortalConfig)) *openAPIPortalFixture {
	t.Helper()
	dbPath := newJWKSE2EDatabase(t)
	logger := zap.NewNop()
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "contract-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Configure(); err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	signing := filepath.Join(t.TempDir(), "signing.pem")
	if err = os.WriteFile(signing, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &authn.PortalConfig{Name: "openapi-contract", IdentityStores: []string{"contract-local"}, CookieConfig: cookie.NewConfig(), API: &authn.APIConfig{ProfileEnabled: profile}, RawCryptoKeyStoreConfig: []string{"crypto default autogenerate tag " + t.Name(), "crypto key signing sign-verify from file " + signing}}
	var admin []string
	for line := range strings.SplitSeq(directives, "\n") {
		if strings.HasPrefix(line, "enable admin") || strings.HasPrefix(line, "disable admin") {
			admin = append(admin, line)
			continue
		}
		if line == "trust login redirect uri domain exact app.example.test path exact /home" {
			redirect, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.test", "exact", "/home")
			if err != nil {
				t.Fatal(err)
			}
			cfg.TrustedLoginRedirectURIConfigs = []*redirects.RedirectURIMatchConfig{redirect}
			continue
		}
		if strings.HasPrefix(line, "crypto key internal system ") {
			cfg.RawCryptoKeyStoreConfig = append(cfg.RawCryptoKeyStoreConfig, line)
			continue
		}
		if line != "" {
			t.Fatalf("unsupported contract fixture directive: %s", line)
		}
	}
	api, err := adminparser.NewAdminAPIConfigFromDirectives(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.ConfigureAdminAPI(api); err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(cfg)
	}
	// Cross the public serialization boundary, preserving actual configuration.
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authn.PortalConfig
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &decoded, Logger: logger, IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mount != "" && !strings.HasPrefix(r.URL.Path, mount+"/") {
			http.NotFound(w, r)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(func() { server.Close(); portal.Close() })
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &openAPIPortalFixture{server: server, portal: portal, database: dbPath, key: private, client: client, base: server.URL, mount: mount, secrets: []string{tests.TestPwd1}}
}
func (f *openAPIPortalFixture) login(t *testing.T, username string) string {
	t.Helper()
	browser := *f.client
	browser.Jar, _ = cookiejar.New(nil)
	fixture := &oidcE2EFixture{server: f.server, client: &browser, issuer: f.base + f.mount}
	webAuthnEnrollmentLogin(t, fixture, username, tests.TestPwd1)
	target, _ := url.Parse(f.base + f.mount + "/api/profile")
	for _, c := range browser.Jar.Cookies(target) {
		if c.Name == "AUTHP_ACCESS_TOKEN" {
			f.secrets = append(f.secrets, c.Value)
			return c.Value
		}
	}
	t.Fatal("browser password login did not issue credentials")
	return ""
}
func registrationHTTP(t *testing.T, client *http.Client, method, target string, form url.Values, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	maps.Copy(req.Header, headers)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("TLS contract request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		t.Fatal("invalid contract response")
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("unverified contract transport")
	}
	return resp.StatusCode, resp.Header, body
}
func (f *openAPIPortalFixture) request(t *testing.T, method, path, token, body string, want int, extras ...http.Header) (http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.base+f.mount+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, h := range extras {
		maps.Copy(req.Header, h)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal("TLS contract request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		t.Fatal("invalid contract response")
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s: HTTP %d, want %d", method, path, resp.StatusCode, want)
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("unverified TLS")
	}
	return resp.Header, raw
}

func openAPIContractValidators(t *testing.T) (openAPIResponseValidator, func(*testing.T, string, any)) {
	t.Helper()
	data, err := openapi.Bundle("../../assets/openapi/content")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	compiler, err := openapi.SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	validateComponent := func(t *testing.T, name string, value any) {
		t.Helper()
		schema, err := openapi.SchemaAt(compiler, "/components/schemas/"+name)
		if err != nil || schema.Validate(value) != nil {
			t.Fatalf("%s schema mismatch (value withheld)", name)
		}
	}
	lookup := func(parts ...string) any {
		var value any = doc
		for _, part := range parts {
			obj, ok := value.(map[string]any)
			if !ok {
				return nil
			}
			value = obj[part]
		}
		return value
	}
	escape := func(value string) string {
		return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
	}
	validate := func(t *testing.T, path, method string, status int, header http.Header, raw []byte) {
		t.Helper()
		parts := []string{"paths", path, strings.ToLower(method), "responses", strconv.Itoa(status)}
		response, ok := lookup(parts...).(map[string]any)
		if !ok {
			t.Fatalf("undocumented response: %s %s %d", method, path, status)
		}
		if ref, ok := response["$ref"].(string); ok {
			parts = strings.Split(strings.TrimPrefix(ref, "#/"), "/")
			response = lookup(parts...).(map[string]any)
		}
		// Redirects may carry a minimal HTML link or omit both body and media
		// type. Ordinary JSON responses still require their documented body.
		if status >= 300 && status < 400 && len(raw) == 0 {
			if header.Get("Location") == "" {
				t.Fatal("redirect omitted its destination")
			}
			return
		}
		if method == "HEAD" || response["content"] == nil {
			if len(raw) != 0 {
				t.Fatalf("%s %s: expected an empty body", method, path)
			}
			return
		}
		media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
		if err != nil {
			t.Fatal("invalid response media type")
		}
		parts = append(parts, "content", media, "schema")
		if lookup(parts...) == nil {
			t.Fatalf("undocumented media type: %s %s %d %s", method, path, status, media)
		}
		pointer := ""
		for _, part := range parts {
			pointer += "/" + escape(part)
		}
		schema, err := openapi.SchemaAt(compiler, pointer)
		if err != nil {
			t.Fatal("could not compile documented response schema")
		}
		var value any
		// Two existing wire quirks are intentional in the specification:
		// beacon is non-JSON despite its media type; metadata is the reverse.
		if path == "/beacon" && status == 200 {
			value = string(raw)
		} else if strings.Contains(media, "json") || path == "/api/server/metadata" && status == 200 {
			value, err = jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		} else {
			value = string(raw)
		}
		if err != nil || schema.Validate(value) != nil {
			t.Fatalf("schema mismatch: %s %s %d %s (body withheld)", method, path, status, media)
		}
	}

	return validate, validateComponent
}
