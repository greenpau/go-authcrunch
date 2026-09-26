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
)

func TestE2EHTMLResponseSecurityHeaders(t *testing.T) {
	fixture := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/auth", nil)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fixture.server.URL+fixture.base+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	response, err := fixture.client.Do(req)
	if err != nil {
		t.Fatal("real TLS portal request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("could not read real TLS portal response")
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `<form`) {
		t.Fatalf("login response status = %d, form present = %t", response.StatusCode, strings.Contains(string(body), `<form`))
	}
	if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := response.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if !strings.Contains(strings.Join(response.Header.Values("Content-Security-Policy"), ";"), "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q", response.Header.Values("Content-Security-Policy"))
	}
}
