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

package util

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBrowserResponseBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write([]byte(strings.Repeat("a", 32)))
		case "/declared-oversized":
			w.Header().Set("Content-Length", strconv.Itoa(33))
			w.WriteHeader(http.StatusOK)
		case "/chunked-oversized":
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = w.Write([]byte(strings.Repeat("b", 33)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	browser, err := NewBrowser()
	if err != nil {
		t.Fatal(err)
	}
	browser.maxResponseBodySize = 32

	request := func(path string) (string, error) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _, err := browser.Do(req)
		return body, err
	}

	body, err := request("/exact")
	if err != nil || body != strings.Repeat("a", 32) {
		t.Fatalf("exact-limit response = %q, %v", body, err)
	}
	for _, path := range []string{"/declared-oversized", "/chunked-oversized"} {
		t.Run(path, func(t *testing.T) {
			if _, err := request(path); !errors.Is(err, ErrHTTPResponseBodyTooLarge) {
				t.Fatalf("error = %v, want %v", err, ErrHTTPResponseBodyTooLarge)
			}
		})
	}
}
