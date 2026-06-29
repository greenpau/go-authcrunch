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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
