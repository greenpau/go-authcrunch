// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestRealmInfoRejectsUnknownRealm(t *testing.T) {
	p := &Portal{logger: zap.NewNop()}
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"unknown realm", `{"realm":"missing","query":"all"}`, http.StatusNotFound},
		{"missing realm", `{"query":"all"}`, http.StatusBadRequest},
		{"invalid request", `{"realm":`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/api/server/info", strings.NewReader(tc.body))
			res := httptest.NewRecorder()
			if err := p.handleAPIRealmInfo(req.Context(), res, req, requests.NewRequest(), nil); err != nil {
				t.Fatal(err)
			}
			if res.Code != tc.status {
				t.Fatalf("got status %d, want %d", res.Code, tc.status)
			}
			var body map[string]any
			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["message"] != http.StatusText(tc.status) {
				t.Fatal("missing realm returned success metadata")
			}
		})
	}
}
