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

	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func TestE2EAdminAPIRequestBodyLimit(t *testing.T) {
	f := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/xauth", &authn.APIConfig{AdminEnabled: true})
	token := f.login(t, "keyadmin")
	request := func(body string) int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server.URL+f.base+"/api/server/realms", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal("admin API request failed")
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
			t.Fatal("admin API response read failed")
		}
		return resp.StatusCode
	}
	if status := request(`{"query":"all"}`); status != http.StatusOK {
		t.Fatalf("ordinary admin request returned HTTP %d", status)
	}
	oversized := `{"query":"` + strings.Repeat("x", 1<<20) + `"}`
	if status := request(oversized); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized admin request returned HTTP %d", status)
	}
}
