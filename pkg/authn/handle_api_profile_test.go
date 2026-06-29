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
)

func TestReadProfileAPIRequestBodyRejectsOversizedBody(t *testing.T) {
	body := strings.NewReader(strings.Repeat("x", int(maxProfileAPIRequestBodySize)+1))
	req := httptest.NewRequest(http.MethodPost, "/profile", body)
	rec := httptest.NewRecorder()

	if _, err := readProfileAPIRequestBody(rec, req); err == nil {
		t.Fatal("expected oversized profile API request body to fail")
	} else if !strings.Contains(err.Error(), "http: request body too large") {
		t.Fatalf("expected request body too large error, got %v", err)
	}
}

func TestGetProfileAPIStringFieldRejectsMalformedValue(t *testing.T) {
	value, exists, ok := getProfileAPIStringField(map[string]interface{}{
		"kind": 42,
	}, "kind")

	if !exists {
		t.Fatal("expected kind field to exist")
	}
	if ok {
		t.Fatal("expected numeric kind field to be malformed")
	}
	if value != "" {
		t.Fatalf("expected empty value for malformed kind field, got %q", value)
	}
}

func TestAddUserAPIKeyRejectsMalformedStringField(t *testing.T) {
	p := &Portal{}
	rr := requests.NewRequest()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/profile", nil)
	resp := make(map[string]interface{})

	if err := p.AddUserAPIKey(
		context.Background(),
		rec,
		req,
		rr,
		nil,
		resp,
		nil,
		nil,
		map[string]interface{}{
			"content":     "test-content",
			"title":       42,
			"description": "",
		},
	); err != nil {
		t.Fatalf("AddUserAPIKey returned error: %v", err)
	}

	if rr.Response.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request status, got %d", rr.Response.Code)
	}
	if got := resp["message"]; got != "Profile API did find title in the request payload, but it is malformed" {
		t.Fatalf("unexpected response message: %v", got)
	}
}
