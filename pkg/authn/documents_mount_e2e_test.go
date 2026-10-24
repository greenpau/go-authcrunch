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
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

type documentsMountBootstrap struct {
	PortalID string `json:"portal_id"`
	UserID   string `json:"user_id"`
}

func TestE2EDocumentsExplicitMount(t *testing.T) {
	for _, mount := range []string{"/", "/tenant/auth"} {
		t.Run(mount, func(t *testing.T) {
			f := newDocumentsE2E(t, mount, true)
			setMount := func(value string) { f.mu.Lock(); f.declaredMount = value; f.mu.Unlock() }
			setMount(mount)
			token := f.login(t, "alice")
			before := documentsDecode[documentsMountBootstrap](t, f.message(t, token, "bootstrap", nil, http.StatusOK))
			key := f.enroll(t, token)
			f.message(t, token, "key.fetch", nil, http.StatusOK)
			// An otherwise valid declaration that disagrees with the opened
			// cryptographic binding must fail before discovery or API dispatch.
			wrong := "/other"
			setMount(wrong)
			for _, suffix := range []string{"/.well-known/jwks.json", "/api/documents/bootstrap"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+wrong+suffix, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := f.client.Do(req)
				if err != nil {
					t.Fatal("Documents mount mismatch request failed")
				}
				_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if readErr != nil || resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Values("Set-Cookie")) != 0 || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
					t.Fatal("Documents mount mismatch reached dispatch or lacked verified TLS")
				}
			}
			setMount(mount)
			after := documentsDecode[documentsMountBootstrap](t, f.message(t, token, "bootstrap", nil, http.StatusOK))
			if before.PortalID == "" || before.UserID == "" || before.PortalID != after.PortalID || before.UserID != after.UserID {
				t.Fatal("rejected declared mount changed persistent Documents ownership")
			}
			fetched := documentsDecode[documents.Key](t, f.message(t, token, "key.fetch", nil, http.StatusOK))
			if fetched.KeyID != key.KeyID {
				t.Fatal("mount rejection changed registered key")
			}
			if mount != "/" {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+strings.Replace(mount, "tenant", "%74enant", 1)+"/api/documents/bootstrap", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := f.client.Do(req)
				if err != nil {
					t.Fatal("encoded Documents mount request failed")
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Values("Set-Cookie")) != 0 {
					t.Fatal("encoded mount escaped boundary")
				}
			}
			f.message(t, token, "bootstrap", nil, http.StatusOK)
		})
	}
}
