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

package authn_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	samllib "github.com/crewjam/saml"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	upstreamsaml "github.com/greenpau/go-authcrunch/pkg/idp/saml"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type samlE2ESPProvider struct{ metadata *samllib.EntityDescriptor }

func (p samlE2ESPProvider) GetServiceProvider(_ *http.Request, entityID string) (*samllib.EntityDescriptor, error) {
	if p.metadata != nil && p.metadata.EntityID == entityID {
		return p.metadata, nil
	}
	return nil, os.ErrNotExist
}

type samlE2ESessionProvider struct{}

func (samlE2ESessionProvider) GetSession(_ http.ResponseWriter, _ *http.Request, _ *samllib.IdpAuthnRequest) *samllib.Session {
	now := time.Now()
	return &samllib.Session{
		ID:             "saml-e2e-session",
		Index:          "saml-e2e-index",
		CreateTime:     now,
		ExpireTime:     now.Add(time.Hour),
		NameID:         "saml-user@example.test",
		UserName:       "saml-user",
		UserEmail:      "saml-user@example.test",
		UserCommonName: "SAML User",
		CustomAttributes: []samllib.Attribute{
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Values: []samllib.AttributeValue{{Type: "xs:string", Value: "saml-user@example.test"}}},
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname", Values: []samllib.AttributeValue{{Type: "xs:string", Value: "SAML User"}}},
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Values: []samllib.AttributeValue{{Type: "xs:string", Value: "saml-user"}}},
		},
	}
}

type samlE2EFixture struct {
	portal    *httptest.Server
	portalURL string
	idp       *httptest.Server
	client    *http.Client
}

func newSAMLE2ESigningKey(t *testing.T, serial int64) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "SAML E2E IdP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func newSAMLE2EFixture(t *testing.T) *samlE2EFixture {
	t.Helper()
	key, cert := newSAMLE2ESigningKey(t, 1)
	rogueKey, rogueCert := newSAMLE2ESigningKey(t, 2)

	portalServer := httptest.NewUnstartedServer(nil)
	_, portalPort, err := net.SplitHostPort(portalServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portalURL := "https://localhost:" + portalPort
	idpServer := httptest.NewUnstartedServer(nil)
	idpURL := "https://" + idpServer.Listener.Addr().String()

	sp := samllib.ServiceProvider{}
	sp.EntityID = "urn:authcrunch:saml:e2e"
	sp.MetadataURL = mustSAMLE2EURL(t, portalURL+"/auth/saml/metadata")
	sp.AcsURL = mustSAMLE2EURL(t, portalURL+"/auth/saml/upstream")
	spProvider := samlE2ESPProvider{metadata: sp.Metadata()}
	idpRuntime := &samllib.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             mustSAMLE2EURL(t, idpURL+"/metadata"),
		SSOURL:                  mustSAMLE2EURL(t, idpURL+"/sso"),
		ServiceProviderProvider: spProvider,
		SessionProvider:         samlE2ESessionProvider{},
		Logger:                  log.New(io.Discard, "", 0),
	}
	rogueRuntime := &samllib.IdentityProvider{
		Key: rogueKey, Certificate: rogueCert, MetadataURL: idpRuntime.MetadataURL, SSOURL: idpRuntime.SSOURL,
		ServiceProviderProvider: spProvider, SessionProvider: samlE2ESessionProvider{}, Logger: log.New(io.Discard, "", 0),
	}
	idpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sso":
			idpRuntime.ServeSSO(w, r)
		case "/rogue-sso":
			rogueRuntime.ServeSSO(w, r)
		case "/metadata":
			idpRuntime.ServeMetadata(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	idpServer.StartTLS()
	t.Cleanup(idpServer.Close)

	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "idp-cert.pem")
	metadataPath := filepath.Join(tmp, "idp-metadata.xml")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	metadataDocument := idpRuntime.Metadata()
	metadataDocument.IDPSSODescriptors[0].KeyDescriptors = append(metadataDocument.IDPSSODescriptors[0].KeyDescriptors, samllib.KeyDescriptor{
		Use: "signing",
		KeyInfo: samllib.KeyInfo{X509Data: samllib.X509Data{X509Certificates: []samllib.X509Certificate{{
			Data: base64.StdEncoding.EncodeToString(rogueCert.Raw),
		}}}},
	})
	metadata, err := xml.Marshal(metadataDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadata, 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := upstreamsaml.NewIdentityProvider(&upstreamsaml.Config{
		Name: "upstream", Realm: "upstream", Driver: "generic",
		IdpMetadataLocation: metadataPath, IdpSignCertLocation: certPath,
		IdpLoginURL: idpURL + "/sso", EntityID: sp.EntityID,
		AssertionConsumerServiceURLs: []string{portalURL + "/auth/saml/upstream", portalURL + "/other/saml/upstream"},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}
	cookies, err := cookieparser.NewCookieConfigFromDirectives([]string{
		"cookie access token name saml_e2e_token",
		"cookie saml session id name SAML_E2E_BROWSER",
	})
	if err != nil {
		t.Fatal(err)
	}
	serializedCookies, err := json.Marshal(cookies)
	if err != nil {
		t.Fatal(err)
	}
	var reloadedCookies cookie.Config
	if err := json.Unmarshal(serializedCookies, &reloadedCookies); err != nil {
		t.Fatal(err)
	}
	if err := reloadedCookies.Validate(); err != nil {
		t.Fatal(err)
	}
	if reloadedCookies.SAMLSessionIDCookieName != "SAML_E2E_BROWSER" {
		t.Fatal("serialized cookie configuration lost custom SAML name")
	}
	portal, err := authn.NewPortal(authn.PortalParameters{
		Config: &authn.PortalConfig{
			Name: "saml-e2e", IdentityProviders: []string{"upstream"},
			RawCryptoKeyStoreConfig: []string{"crypto default autogenerate tag saml-e2e", "crypto default token name saml_e2e_token"},
			CookieConfig:            &reloadedCookies,
		},
		Logger:            zap.NewNop(),
		IdentityProviders: []idp.IdentityProvider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(portal.Close)
	portalServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("portal execution failed", err)
		}
	})
	portalServer.StartTLS()
	t.Cleanup(portalServer.Close)

	pool := x509.NewCertPool()
	pool.AddCert(portalServer.Certificate())
	pool.AddCert(idpServer.Certificate())
	// Both httptest listeners use the loopback certificate. Override TLS name
	// resolution while retaining the public localhost host needed for SameSite.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &samlE2EFixture{portal: portalServer, portalURL: portalURL, idp: idpServer, client: client}
}

func mustSAMLE2EURL(t *testing.T, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return *u
}

var samlE2EInput = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

func (f *samlE2EFixture) begin(t *testing.T) url.Values {
	return f.beginWithSigner(t, false)
}

func (f *samlE2EFixture) beginWithSigner(t *testing.T, rogue bool) url.Values {
	t.Helper()
	resp, err := f.client.Get(f.portalURL + "/auth/saml/upstream")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("SAML initiation returned HTTP %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("SAMLRequest") == "" || u.Query().Get("RelayState") == "" {
		t.Fatal("SAML initiation omitted request or RelayState")
	}
	if rogue {
		u.Path = "/rogue-sso"
		location = u.String()
	}
	resp, err = f.client.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SAML IdP returned HTTP %d", resp.StatusCode)
	}
	form := url.Values{}
	for _, match := range samlE2EInput.FindAllStringSubmatch(string(body), -1) {
		form.Set(match[1], html.UnescapeString(match[2]))
	}
	if form.Get("SAMLResponse") == "" || form.Get("RelayState") == "" {
		t.Fatal("signed IdP response omitted SAMLResponse or RelayState")
	}
	return form
}

func samlE2EPost(t *testing.T, client *http.Client, endpoint string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(endpoint, form)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp
}

func TestE2ESAMLResponseBoundToBrowserRequestAndCallback(t *testing.T) {
	f := newSAMLE2EFixture(t)
	endpoint := f.portalURL + "/auth/saml/upstream"

	t.Run("missing state", func(t *testing.T) {
		form := f.begin(t)
		form.Del("RelayState")
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("missing RelayState returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
	})

	t.Run("wrong browser and callback do not consume state", func(t *testing.T) {
		form := f.begin(t)
		otherJar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		otherClient := *f.client
		otherClient.Jar = otherJar
		if resp := samlE2EPost(t, &otherClient, endpoint, form); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong browser returned HTTP %d", resp.StatusCode)
		}
		if resp := samlE2EPost(t, f.client, f.portalURL+"/other/saml/upstream", form); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong callback returned HTTP %d", resp.StatusCode)
		}
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Authorization") == "" {
			t.Fatalf("matching signed callback returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("replay returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
	})

	t.Run("duplicate domain-cookie collision is rejected", func(t *testing.T) {
		form := f.begin(t)
		body := strings.NewReader(form.Encode())
		req, err := http.NewRequest(http.MethodPost, endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", "SAML_E2E_BROWSER=attacker")
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("duplicate binding cookie returned HTTP %d", resp.StatusCode)
		}
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Authorization") == "" {
			t.Fatalf("duplicate cookie attempt consumed state: HTTP %d", resp.StatusCode)
		}
	})

	t.Run("relay state is not a destination", func(t *testing.T) {
		form := f.begin(t)
		form.Set("RelayState", f.portalURL+"/other/saml/upstream")
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("destination-shaped RelayState returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
	})

	t.Run("response is bound to authentication request", func(t *testing.T) {
		first, second := f.begin(t), f.begin(t)
		second.Set("RelayState", first.Get("RelayState"))
		if resp := samlE2EPost(t, f.client, endpoint, second); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("response from another request returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
	})

	t.Run("metadata signing key cannot override configured pin", func(t *testing.T) {
		form := f.beginWithSigner(t, true)
		if resp := samlE2EPost(t, f.client, endpoint, form); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
			t.Fatalf("metadata rogue key returned HTTP %d with authorization %q", resp.StatusCode, resp.Header.Get("Authorization"))
		}
	})
}

// Chrome enforces SameSite on the cross-site IdP POST and isolates browser
// contexts, covering behavior that net/http's cookie jar cannot model.
func TestE2ESAMLBrowserCrossSitePOSTBinding(t *testing.T) {
	f := newSAMLE2EFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	profile := t.TempDir()
	spki := make([]string, 0, 2)
	for _, server := range []*httptest.Server{f.portal, f.idp} {
		sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
		spki = append(spki, base64.StdEncoding.EncodeToString(sum[:]))
	}
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+strings.Join(spki, ","),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
		"--disable-crash-reporter", "--no-proxy-server", "--host-resolver-rules=MAP localhost 127.0.0.1",
		"--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	params, err := json.Marshal(map[string]string{"portal": f.portalURL})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "ui/testdata/saml_browser_e2e.cjs", endpoint, string(params))
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("SAML browser regression failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not confirm SAML binding")
	}
}
