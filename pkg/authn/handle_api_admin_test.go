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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func TestAdminAPIRequestBodyLimit(t *testing.T) {
	p := &Portal{logger: zap.NewNop()}
	type handler func(context.Context, http.ResponseWriter, *http.Request, *requests.Request, *user.User) error
	for _, tc := range []struct {
		name string
		call handler
	}{
		{"realms", p.handleAPIListRealms},
		{"users", p.handleAPIListUsers},
		{"user", p.handleAPICrudUser},
		{"info", p.handleAPIRealmInfo},
		{"reload", p.handleAPIReloadRealm},
	} {
		t.Run(tc.name+" rejects oversized JSON", func(t *testing.T) {
			body := `{"realm":"` + strings.Repeat("x", int(maxAdminAPIRequestBodySize)) + `"}`
			req := httptest.NewRequest(http.MethodPost, "/auth/api/server/"+tc.name, strings.NewReader(body))
			res := httptest.NewRecorder()
			if err := tc.call(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
				t.Fatal(err)
			}
			if res.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("got status %d, want %d", res.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}

	t.Run("accepts JSON at limit", func(t *testing.T) {
		const envelope = `{"query":""}`
		body := `{"query":"` + strings.Repeat("x", int(maxAdminAPIRequestBodySize)-len(envelope)) + `"}`
		if int64(len(body)) != maxAdminAPIRequestBodySize {
			t.Fatal("test body does not exercise exact limit")
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/api/server/realms", strings.NewReader(body))
		res := httptest.NewRecorder()
		if err := p.handleAPIListRealms(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
			t.Fatal(err)
		}
		if res.Code != http.StatusOK {
			t.Fatalf("got status %d, want %d", res.Code, http.StatusOK)
		}
	})
}
