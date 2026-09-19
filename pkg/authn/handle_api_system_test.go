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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestReadSystemAPIRequestBodyRejectsOversizedBody(t *testing.T) {
	body := strings.NewReader(strings.Repeat("x", int(maxSystemAPIRequestBodySize)+1))
	req := httptest.NewRequest(http.MethodPost, "/api/system", body)
	rec := httptest.NewRecorder()

	if _, err := readSystemAPIRequestBody(rec, req); err == nil {
		t.Fatal("expected oversized system API request body to fail")
	} else if !strings.Contains(err.Error(), "http: request body too large") {
		t.Fatalf("expected request body too large error, got %v", err)
	}
}

type systemBodyReadError struct{ closed bool }

func (*systemBodyReadError) Read([]byte) (int, error) {
	return 0, errors.New("request body unavailable")
}
func (b *systemBodyReadError) Close() error { b.closed = true; return nil }

func TestSystemAPIRequestBodyErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		status int
	}{
		{"oversized", int(maxSystemAPIRequestBodySize) + 1, http.StatusRequestEntityTooLarge},
		{"read failure", 0, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("body read error panicked: %v", recovered)
				}
			}()
			bodyError := &systemBodyReadError{}
			var body io.ReadCloser = bodyError
			if tc.size != 0 {
				body = io.NopCloser(strings.NewReader(strings.Repeat("x", tc.size)))
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/api/system", body)
			rec := httptest.NewRecorder()
			if err := (&Portal{}).handleAPISystem(t.Context(), rec, req, requests.NewRequest(), nil); err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.status || result["error"] != http.StatusText(tc.status) {
				t.Fatalf("body error returned %d: %s", rec.Code, rec.Body.String())
			}
			if tc.size == 0 && !bodyError.closed {
				t.Fatal("failed request body was not closed")
			}
		})
	}
}
