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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	attachmentparser "github.com/greenpau/go-authcrunch/pkg/identity/attachment/parser"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/system"
	"go.uber.org/zap"
)

// A bounded TLS LDAP fixture exercises actual bind/search messages. Directory
// passwords and attributes never come from portal internals or forged JWTs.
func connectedLDAPServer(t *testing.T) string {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	certificates := certServer.TLS.Certificates
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				send := func(id int64, op *ber.Packet) bool {
					message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
					message.AppendChild(op)
					_, err := conn.Write(message.Bytes())
					return err == nil
				}
				result := func(id int64, tag ber.Tag, code int) bool {
					op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
					op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
					op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					return send(id, op)
				}
				for {
					message, err := ber.ReadPacket(conn)
					if err != nil || len(message.Children) < 2 {
						return
					}
					id, ok := message.Children[0].Value.(int64)
					if !ok {
						return
					}
					op := message.Children[1]
					switch op.Tag {
					case 0:
						if len(op.Children) != 3 {
							return
						}
						dn, _ := op.Children[1].Value.(string)
						password := op.Children[2].Data.String()
						code := 49
						if dn == "cn=service,dc=example,dc=test" && password == "service-password" || dn == "uid=alice,dc=example,dc=test" && password == tests.TestPwd1 {
							code = 0
						}
						if !result(id, 1, code) {
							return
						}
					case 3:
						entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
						entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice,dc=example,dc=test", ""))
						attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						for key, value := range map[string]string{"givenName": "Alice", "sn": "Directory", "sAMAccountName": "alice", "mail": "alice@example.test"} {
							attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
							attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, key, ""))
							values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
							values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
							attribute.AppendChild(values)
							attrs.AppendChild(attribute)
						}
						entry.AppendChild(attrs)
						if !send(id, entry) || !result(id, 5, 0) {
							return
						}
					default:
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	return "ldaps://" + listener.Addr().String()
}

func TestE2EConnectedLDAPIdentity(t *testing.T) {
	directory := connectedLDAPServer(t)
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprintf("attached=%t", attached), func(t *testing.T) {
			path := newJWKSE2EDatabase(t)
			local, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "local", Kind: "local", Params: map[string]any{"path": path, "realm": "local"}}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := local.Configure(); err != nil {
				t.Fatal(err)
			}
			params := map[string]any{"realm": "directory", "servers": []map[string]any{{"address": directory, "ignore_cert_errors": true, "timeout": 5}}, "bind_username": "cn=service,dc=example,dc=test", "bind_password": "service-password", "search_base_dn": "dc=example,dc=test", "groups": []map[string]any{{"dn": "cn=members,dc=example,dc=test", "roles": []string{"authp/user"}}}, "fallback_roles": []string{"authp/user"}}
			if attached {
				config, err := attachmentparser.NewIdentityAttachmentConfigFromDirectives([]string{"attach to local identity store local"})
				if err != nil {
					t.Fatal(err)
				}
				params["attachment"] = config
			}
			ldap, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "ldap", Kind: "ldap", Params: params}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := ldap.Configure(); err != nil {
				t.Fatal(err)
			}
			portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{Name: "ldap", IdentityStores: []string{"local", "ldap"}, CookieConfig: cookie.NewConfig(), RawCryptoKeyStoreConfig: []string{"crypto key portal sign-verify " + oidcE2EPortalSecret, "crypto key internal system " + challengeSystemKey}}, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{local, ldap}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(portal.Close)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
					t.Error("LDAP portal failed")
				}
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client.Timeout = 10 * time.Second
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			f := &oidcE2EFixture{server: server, client: client, issuer: server.URL + "/auth"}
			directLogin := func(wantID, wantRole string, status int) {
				t.Helper()
				checkClaims := func(claims map[string]any) {
					t.Helper()
					if claims["id"] != wantID || claims["sub"] != "alice" || fmt.Sprint(claims["amr"]) != "[federated]" || wantRole != "" && !strings.Contains(fmt.Sprint(claims["roles"]), wantRole) {
						t.Fatal("direct directory authentication lost attached identity, roles or verified methods")
					}
				}
				basic := &authproxy.Request{Realm: "directory", Secret: base64.StdEncoding.EncodeToString([]byte("alice:" + tests.TestPwd1)), Address: "127.0.0.1"}
				err := portal.BasicAuth(basic)
				if status == http.StatusOK {
					if err != nil {
						t.Fatal("direct directory authentication failed", err)
					}
					checkClaims(providerRefreshClaims(t, &http.Cookie{Value: basic.Response.Payload}))
				} else if err == nil || basic.Response.Payload != "" {
					t.Fatal("directory Basic authentication bypassed attached local policy")
				}
				encoded, err := challengeSystemEncryptor(t).EncryptMessage(&system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "directory", Username: "alice", Password: tests.TestPwd1, Address: "198.51.100.10"})
				if err != nil {
					t.Fatal(err)
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/system", strings.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "text/plain; charset=UTF-8")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != status {
					t.Fatalf("directory system authentication HTTP %d, want %d", response.StatusCode, status)
				}
				if status == http.StatusOK {
					checkClaims(challengeSystemClaims(t, data))
				}
			}
			origin := http.Header{"Origin": {server.URL}}
			login := func(username, password string) oidcE2EResponse {
				oidcE2EStatus(t, f.request(t, "GET", "/login?fresh=1", nil, nil), 200)
				start := f.request(t, "POST", "/login?fresh=1", url.Values{"username": {username}, "realm": {"directory"}}, origin)
				oidcE2EStatus(t, start, 303)
				sandbox := start.header.Get("Location")
				verified := f.request(t, "POST", sandbox, url.Values{"secret": {password}}, origin)
				if password != tests.TestPwd1 {
					return verified
				}
				oidcE2EStatus(t, verified, 303)
				return f.request(t, "GET", sandbox, nil, nil)
			}
			failed := login("alice", "incorrect-password")
			if failed.header.Get("Authorization") != "" {
				t.Fatal("wrong directory password authenticated")
			}
			db, err := identity.NewDatabase(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(db.Users) != 2 {
				t.Fatal("failed directory login provisioned an identity")
			}
			var id string
			for _, username := range []string{"alice", "alice@example.test"} {
				oidcE2EStatus(t, login(username, tests.TestPwd1), 303)
				claims := providerRefreshClaims(t, &http.Cookie{Value: loginIdentityCookie(f, "AUTHP_ACCESS_TOKEN")})
				got, _ := claims["id"].(string)
				if got == "" || id != "" && got != id {
					t.Fatal("directory aliases did not resolve to one local ID")
				}
				id = got
			}
			directLogin(id, "authp/user", http.StatusOK)
			db, err = identity.NewDatabase(path)
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if attached {
				want = 3
			}
			if len(db.Users) != want {
				t.Fatal("directory attachment used wrong store")
			}
			if attached {
				var username string
				for _, u := range db.Users {
					if u.ID == id {
						username = u.Username
						if len(u.ExternalAccounts) != 1 || u.ExternalAccounts[0].Subject != "uid=alice,dc=example,dc=test" {
							t.Fatal("directory DN was not retained")
						}
					}
				}
				if username == "" {
					t.Fatal("local directory identity missing")
				}
				account := identity.ExternalAccount{Provider: "ldap", Kind: "ldap", Issuer: "directory", Subject: "uid=alice,dc=example,dc=test"}
				source, err := db.ResolveExternalAccount(t.Context(), account, false)
				if err != nil {
					t.Fatal(err)
				}
				target := &requests.Request{User: requests.User{Username: "keymember", Password: tests.TestPwd1}}
				if err := db.AuthenticateUser(target); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ConnectExternalAccount(t.Context(), account, source.Evidence, target.Authentication); err != nil {
					t.Fatal(err)
				}
				if err := db.AddUserRoles(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test", Roles: []string{"attached-role"}}}); err != nil {
					t.Fatal(err)
				}
				directLogin(target.Authentication.UserID, "attached-role", http.StatusOK)
				if err := db.OverwriteUserAuthChallengeRules(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test", Challenges: []string{"password"}}}); err != nil {
					t.Fatal(err)
				}
				directLogin("", "", http.StatusForbidden)
				if err := db.OverwriteUserAuthChallengeRules(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}}); err != nil {
					t.Fatal(err)
				}
				if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "keymember", Email: "keymember@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "directory login", Secret: loginIdentityTOTPSecret, Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true}}); err != nil {
					t.Fatal(err)
				}
				directLogin("", "", http.StatusForbidden)
				browserBasic := f.request(t, http.MethodGet, "/basic/login/directory", nil, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+tests.TestPwd1))}})
				oidcE2EStatus(t, browserBasic, http.StatusSeeOther)
				if !strings.Contains(browserBasic.header.Get("Location"), "/sandbox/") || browserBasic.header.Get("Authorization") != "" {
					t.Fatal("browser Basic login issued access before attached MFA")
				}
				// The client keeps the public directory username/realm while the
				// server verifies the linked account's local factor.
				req := apiauth.AuthRequest{Username: "alice", Realm: "directory"}
				startJSON := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
				req.SandboxID, req.SandboxSecret = startJSON.SandboxID, startJSON.SandboxSecret
				req.ChallengeKind, req.ChallengeResponse = startJSON.NextChallenge, tests.TestPwd1
				factor := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
				if factor.Authenticated || factor.NextChallenge == "" {
					t.Fatal("directory password bypassed attached MFA")
				}
				req.SandboxID, req.SandboxSecret = factor.SandboxID, factor.SandboxSecret
				req.ChallengeKind, req.ChallengeResponse = factor.NextChallenge, loginIdentityTOTP()
				completedJSON := loginIdentityResponse(t, f.jsonRequest(t, "/login", req, "", origin))
				if !completedJSON.Authenticated {
					t.Fatal("directory and local factor did not complete")
				}
				claims := providerRefreshClaims(t, &http.Cookie{Value: completedJSON.AccessToken})
				if claims["id"] != target.Authentication.UserID || !strings.Contains(fmt.Sprint(claims["amr"]), "otp") {
					t.Fatal("attached directory MFA identity missing")
				}
				db, err = identity.NewDatabase(path)
				if err != nil {
					t.Fatal(err)
				}
				username = "keymember"
				if err := db.DisableUser(&requests.Request{User: requests.User{Username: username, Email: "keymember@example.test"}}); err != nil {
					t.Fatal(err)
				}
				directLogin("", "", http.StatusUnauthorized)
				oidcE2EStatus(t, f.request(t, "GET", "/login?fresh=1", nil, nil), 200)
				start := f.request(t, "POST", "/login?fresh=1", url.Values{"username": {"alice"}, "realm": {"directory"}}, origin)
				denied := f.request(t, "POST", start.header.Get("Location"), url.Values{"secret": {tests.TestPwd1}}, origin)
				if denied.header.Get("Authorization") != "" {
					t.Fatal("disabled local identity authenticated through directory")
				}
			}
		})
	}
}
