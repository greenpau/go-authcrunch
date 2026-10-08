// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0
package authn_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

func testOpenAPIRegistration(t *testing.T, validate openAPIResponseValidator) {
	dir := t.TempDir()
	outbox, dropbox := filepath.Join(dir, "mail"), filepath.Join(dir, "registrations.json")
	portal := newOpenAPIPortalFixtureWithConfig(t, "/auth", "", false, func(c *authn.PortalConfig) { c.UserRegistries = []string{"contract_signup"} })
	definition := &registry.LocalUserRegistryProvider{Name: "contract_signup", Dropbox: dropbox, EmailProviderName: "contract_mail", AdminEmails: []string{"admin@example.test"}, IdentityStoreName: "contract-local", RealmName: "local", RequireAcceptTerms: true, Code: "invitation", DomainRestrictions: []string{cfg.EncodeArgs([]string{"allow", "domain", "example.test"})}}
	if err := definition.SetMessaging(&messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "contract_mail", RootDir: outbox, SenderEmail: "registration@example.test"}}}); err != nil {
		t.Fatal(err)
	}
	signup, err := definition.NewRuntime(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signup.Close)
	if err = portal.portal.AddUserRegistry(signup); err != nil {
		t.Fatal(err)
	}
	f := struct {
		*oidcE2EFixture
		base, database string
	}{&oidcE2EFixture{server: portal.server, client: portal.client, issuer: portal.base + portal.mount}, portal.base, portal.database}
	form := url.Values{"registrant": {"newuser"}, "registrant_email": {"newuser@example.test"}, "registrant_password": {"RegistrationPlaintext42!"}, "registrant_code": {"invitation"}, "accept_terms": {"on"}}
	mailFiles := func() []string {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(outbox, "*.eml"))
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	// The unscoped route never selects a default registry. Only the realm
	// route displays the form and accepts a registration submission.
	for _, method := range []string{"GET", "POST"} {
		t.Run("missing realm "+method, func(t *testing.T) {
			var body url.Values
			if method == "POST" {
				body = form
			}
			r := f.request(t, method, f.issuer+"/register", body, nil)
			r.requireStatus(t, http.StatusBadRequest)
			validate(t, "/register", method, r.status, r.header, r.body)
			if len(mailFiles()) != 0 {
				t.Fatal("unscoped registration sent a confirmation")
			}
		})
	}
	landing := f.request(t, "GET", f.issuer+"/register/local", nil, nil)
	landing.requireStatus(t, http.StatusOK)
	validate(t, "/register/{realm}", "GET", landing.status, landing.header, landing.body)
	if !bytes.Contains(landing.body, []byte(`name="registrant"`)) {
		t.Fatal("realm registration did not display the form")
	}
	submit := func(body, media string, chunked bool) oidcE2EResponse {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+"/register/local", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", media)
		if chunked {
			req.ContentLength = -1
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal("registration HTTP request failed")
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		validate(t, "/register/{realm}", "POST", resp.StatusCode, resp.Header, data)
		return oidcE2EResponse{resp.StatusCode, resp.Header, data}
	}
	for _, tc := range []struct {
		name, body, media string
		chunked           bool
	}{
		{"short body", "a=1", "application/x-www-form-urlencoded", false},
		{"oversized body", form.Encode() + "&padding=" + strings.Repeat("x", 1001), "application/x-www-form-urlencoded", false},
		{"charset rejected", form.Encode(), "application/x-www-form-urlencoded; charset=utf-8", false},
		{"unknown length", form.Encode(), "application/x-www-form-urlencoded", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := submit(tc.body, tc.media, tc.chunked)
			r.requireStatus(t, 200)
			if !bytes.Contains(r.body, []byte("Registration request is non compliant")) || len(mailFiles()) != 0 {
				t.Fatal("registration admission rule differs from documented contract")
			}
		})
	}
	for _, field := range []string{"registrant_code", "accept_terms", "registrant_email"} {
		candidate := url.Values{}
		for k, v := range form {
			candidate[k] = append([]string(nil), v...)
		}
		candidate.Set(field, "invalid")
		if field == "registrant_email" {
			candidate.Set(field, "newuser@other.test")
		}
		submit(candidate.Encode(), "application/x-www-form-urlencoded", false).requireStatus(t, 200)
		if len(mailFiles()) != 0 {
			t.Fatal("invalid registration sent confirmation")
		}
	}
	submit(form.Encode(), "application/x-www-form-urlencoded", false).requireStatus(t, 200)
	files := mailFiles()
	if len(files) != 1 {
		t.Fatal("registration did not emit one local confirmation")
	}
	message, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	email, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil || email.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatal("invalid confirmation email encoding")
	}
	content, err := io.ReadAll(quotedprintable.NewReader(email.Body))
	if err != nil {
		t.Fatal("could not decode confirmation email")
	}
	link := regexp.MustCompile(`href="([^"]+/register/local/ack/[A-Za-z0-9]+)"`).FindSubmatch(content)
	code := regexp.MustCompile(`<b><code>([A-Za-z0-9]+)</code></b>`).FindSubmatch(content)
	if len(link) != 2 || len(code) != 2 {
		t.Fatal("confirmation message omitted link or code")
	}
	ackURL, err := url.Parse(string(link[1]))
	if err != nil || ackURL.Scheme+"://"+ackURL.Host != f.base {
		t.Fatal("confirmation link left the fixture origin")
	}
	const ackPath = "/register/{realm}/ack/{registration_id}"
	r := f.request(t, "GET", ackURL.String(), nil, nil)
	r.requireStatus(t, http.StatusOK)
	validate(t, ackPath, "GET", r.status, r.header, r.body)
	if !bytes.Contains(r.body, []byte(`name="registration_code"`)) || len(mailFiles()) != 1 || openAPIRegistrationRecord(t, dropbox, "newuser") != nil {
		t.Fatal("opening confirmation must display the code form without confirming registration")
	}
	r = f.request(t, "POST", ackURL.String(), url.Values{"registration_code": {"incorrect"}}, nil)
	validate(t, ackPath, "POST", r.status, r.header, r.body)
	if !bytes.Contains(r.body, []byte("Registration identifier mismatch")) {
		t.Fatal("wrong confirmation code was not rejected")
	}
	if openAPIRegistrationRecord(t, f.database, "newuser") != nil {
		t.Fatal("pending registration created a login user")
	}
	r = f.request(t, "POST", ackURL.String(), url.Values{"registration_code": {" \t" + string(code[1]) + "\n"}}, nil)
	r.requireStatus(t, 200)
	validate(t, ackPath, "POST", r.status, r.header, r.body)
	if len(mailFiles()) != 2 || openAPIRegistrationRecord(t, dropbox, "newuser") == nil || openAPIRegistrationRecord(t, f.database, "newuser") != nil {
		t.Fatal("confirmation did not preserve the dropbox/active-account boundary")
	}
	r = f.request(t, "POST", ackURL.String(), url.Values{"registration_code": {string(code[1])}}, nil)
	validate(t, ackPath, "POST", r.status, r.header, r.body)
	if !bytes.Contains(r.body, []byte("Registration identifier not found")) || len(mailFiles()) != 2 {
		t.Fatal("confirmation replay was not rejected")
	}
}

func (r oidcE2EResponse) requireStatus(t *testing.T, want int) { t.Helper(); oidcE2EStatus(t, r, want) }
func openAPIRegistrationRecord(t *testing.T, path, username string) *identity.User {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var db identity.Database
	if err = json.Unmarshal(data, &db); err != nil {
		t.Fatal(err)
	}
	for _, user := range db.Users {
		if user.Username == username {
			return user
		}
	}
	return nil
}
