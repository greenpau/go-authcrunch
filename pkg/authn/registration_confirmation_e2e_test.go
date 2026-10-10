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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// Embedding the legacy implementation exposes accidental fallback through real
// persisted accounts and notifications, while the optional hook rejects access.
type rejectingRegistration struct {
	*registry.LocalUserRegistryProvider
	called atomic.Int32
}

func (r *rejectingRegistration) ConfirmRegistration(context.Context, string, string) error {
	r.called.Add(1)
	return fmt.Errorf("synthetic private backend error")
}
func TestE2ERegistrationConfirmationCapability(t *testing.T) {
	for _, capability := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability_%t", capability), func(t *testing.T) {
			f := newRefreshPortal(t, false, false)
			f.portal.config.UserRegistries = []string{"enrollment"}
			destination := "https://trusted.example.test/registration"
			trusted, err := redirects.NewRedirectURIMatchConfig("exact", "trusted.example.test", "prefix", "/")
			if err != nil {
				t.Fatal(err)
			}
			f.portal.config.TrustedLoginRedirectURIConfigs = []*redirects.RedirectURIMatchConfig{trusted}
			dbPath := filepath.Join(t.TempDir(), "registrations.json")
			config := &registry.LocalUserRegistryProvider{Name: "enrollment", Dropbox: dbPath, IdentityStoreName: "localdb", RealmName: "local", EmailProviderName: "file", AdminEmails: []string{"admin@example.test"}}
			provider, err := config.NewRuntime(zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			if err := provider.SetMessaging(&messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "file", RootDir: filepath.Join(t.TempDir(), "mail"), SenderEmail: "auth@example.test"}}}); err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("a", 64)
			if err := provider.AddRegistrationEntry(id, map[string]string{"username": "alice", "email": "alice@example.test", "password": "Synthetic-registration-password-2026!", "registration_code": "ABC123", "realm_name": "local", "return_url": destination}); err != nil {
				t.Fatal(err)
			}
			rejecting := &rejectingRegistration{LocalUserRegistryProvider: provider}
			var selected registry.Provider = provider
			if capability {
				selected = rejecting
			}
			if err := f.portal.AddUserRegistry(selected); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := f.portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			form := url.Values{"registration_code": {"ABC123"}}
			response, err := server.Client().PostForm(server.URL+"/auth/register/local/ack/"+id+"?redirect_url="+url.QueryEscape("https://trusted.example.test/override"), form)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatal("confirmation response", err)
			}
			persisted, err := identity.NewDatabase(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			query := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
			accountErr := persisted.GetUser(query)
			_, pendingErr := provider.GetRegistrationEntry(id)
			if capability {
				if rejecting.called.Load() != 1 || accountErr == nil || pendingErr != nil || !strings.Contains(string(body), "Registration confirmation denied") || strings.Contains(string(body), "synthetic private backend error") {
					t.Fatal("capability failure fell through, consumed pending entry, or leaked error")
				}
			} else {
				if accountErr != nil || pendingErr == nil {
					t.Fatal("legacy registration sequence changed", accountErr, pendingErr)
				}
				if !strings.Contains(string(body), "redirect_url="+url.QueryEscape(destination)) || strings.Contains(string(body), "redirect_url="+url.QueryEscape("https://trusted.example.test/override")) {
					t.Fatal("legacy confirmation lost its bound destination")
				}
			}
		})
	}
}
