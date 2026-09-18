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

package uri_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/greenpau/go-authcrunch/pkg/authz/internal/uri"
)

func TestRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		want       []string
	}{
		{"empty", "", []string{"/"}},
		{"clean before decode", "/public/a%2fb/../%2e%2e/admin", []string{"/public/a%2fb/../%2e%2e/admin", "/public/%2e%2e/admin", "/public/a/b/../../admin", "/public/admin", "/public/../admin", "/admin"}},
		{"root", "/", []string{"/"}},
		{"relative", "public/file", []string{"/public/file"}},
		{"relative traversal", "../public/", []string{"/../public/", "/public/"}},
		{"slashes", "/public//assets/", []string{"/public//assets/", "/public/assets/"}},
		{"literal traversal", "/public/../admin", []string{"/public/../admin", "/admin"}},
		{"dot encoding", "/public/%2e%2e/admin", []string{"/public/%2e%2e/admin", "/public/../admin", "/admin"}},
		{"slash encoding", "/public/..%2Fadmin", []string{"/public/..%2Fadmin", "/public/../admin", "/admin"}},
		{"encoded trailing slash", "/public%2f", []string{"/public%2f", "/public/"}},
		{"ordinary encoding", "/public/%41+file", []string{"/public/%41+file", "/public/A+file"}},
		{"intermediate private path", "/public/%2e%2e/admin/%252e%252e/public/file", []string{"/public/%2e%2e/admin/%252e%252e/public/file", "/public/../admin/%2e%2e/public/file", "/admin/%2e%2e/public/file", "/public/../admin/../public/file", "/public/file", "/admin/../public/file"}},
		{"literal non-escape", "/public/%zz", []string{"/public/%zz"}},
		{"literal short percent text", "/public/%2", []string{"/public/%2"}},
		{"literal percent", "/public/100%", []string{"/public/100%"}},
		{"decoded literal non-escape", "/public/%25zz", []string{"/public/%25zz", "/public/%zz"}},
		{"malformed escape beside traversal", "/public/%zz/%2e%2e/admin", nil},
		{"malformed first hex", "/public/%z1/%2e%2e/admin", nil},
		{"malformed last hex", "/public/%1z/%2e%2e/admin", nil},
		{"escaped segment removed by cleaning", "/%41/../public", []string{"/%41/../public", "/public", "/A/../public"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, valid := requestPaths(tc.path)
			if valid != (tc.want != nil) || !cmp.Equal(got, tc.want) {
				t.Fatalf("RequestPaths(%q) = %q, %t; want %q", tc.path, got, valid, tc.want)
			}
		})
	}
}

func TestRequestPathsDecodeLimit(t *testing.T) {
	value := "/public/%2e%2e/admin"
	for depth := 1; depth <= 6; depth++ {
		got, valid := requestPaths(value)
		if depth <= 4 {
			if !valid || got[len(got)-1] != "/admin" {
				t.Fatalf("depth %d: got %q, valid=%t", depth, got, valid)
			}
		} else if valid || got != nil {
			t.Fatalf("depth %d: unresolved encodings were accepted", depth)
		}
		value = strings.ReplaceAll(value, "%", "%25")
	}
}

func FuzzRequestPaths(f *testing.F) {
	for _, seed := range []string{"", "/public/", "/public/%2e%2e/admin", "/public/%25zz", "../public/", "/public/%252525252e/admin", "/public/a%2fb/../%2e%2e/admin", "/admin/../public/file", "/public%2Fadmin", "/public/admin/%2e/../file"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		requests := []*http.Request{{URL: &url.URL{Path: value}}}
		if parsed, err := url.ParseRequestURI(value); err == nil {
			requests = append(requests, &http.Request{Method: http.MethodGet, URL: parsed})
		}
		for _, req := range requests {
			paths, valid := uri.RequestPaths(req)
			if !valid {
				if paths != nil {
					t.Fatal("invalid input returned usable paths")
				}
				continue
			}
			original := req.URL.Path
			if !strings.HasPrefix(original, "/") {
				original = "/" + original
			}
			if !slices.Contains(paths, original) {
				t.Fatal("authorization lost the supplied path")
			}
			if len(paths) == 0 || len(paths) > 124 {
				t.Fatal("unbounded or empty path interpretations")
			}
			for _, candidate := range paths {
				if !utf8.ValidString(candidate) {
					t.Fatal("authorization accepted invalid UTF-8")
				}
				cleaned := path.Clean(candidate)
				if strings.HasSuffix(candidate, "/") && cleaned != "/" {
					cleaned += "/"
				}
				if !slices.Contains(paths, cleaned) {
					t.Fatal("cleaning produced an unchecked path")
				}
				decoded, err := url.PathUnescape(candidate)
				if err == nil && !slices.Contains(paths, decoded) {
					t.Fatal("decoding produced an unchecked path")
				}
				if !strings.HasPrefix(candidate, "/") {
					t.Fatal("path is not absolute")
				}
			}
		}
	})
}

func TestRequestPathsHTTPParsing(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"/public/%2e%2e/admin", "/admin"},
		{"/public/%252e%252e/admin", "/admin"},
		{"/public/%2e/assets/logo.png", "/public/assets/logo.png"},
		{"/public//assets/", "/public/assets/"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			paths, valid := uri.RequestPaths(r)
			if !valid || !slices.Contains(paths, tc.want) {
				t.Fatalf("paths=%q valid=%t want interpretation=%q; Path=%q RawPath=%q RequestURI=%q", paths, valid, tc.want, r.URL.Path, r.URL.RawPath, r.RequestURI)
			}
		})
	}
}

func requestPaths(value string) ([]string, bool) {
	return uri.RequestPaths(&http.Request{URL: &url.URL{Path: value}})
}

func TestRequestPathsRequestTargets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		req   *http.Request
		valid bool
	}{
		{"nil", nil, false},
		{"missing URL", &http.Request{}, false},
		{"CONNECT authority", httptest.NewRequest(http.MethodConnect, "example.com:443", nil), false},
		{"CONNECT path", httptest.NewRequest(http.MethodConnect, "/rpc", nil), true},
		{"opaque target", httptest.NewRequest(http.MethodGet, "mailto:admin@example.com", nil), false},
		{"asterisk", httptest.NewRequest(http.MethodOptions, "*", nil), false},
		{"absolute root", httptest.NewRequest(http.MethodGet, "http://example.com", nil), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, valid := uri.RequestPaths(tc.req)
			if valid != tc.valid || (!valid && paths != nil) {
				t.Fatalf("paths=%q valid=%t, want valid=%t", paths, valid, tc.valid)
			}
		})
	}
}

func TestRequestPathsEscapedRouting(t *testing.T) {
	for _, target := range []string{
		"/public%2fadmin", "/public%2Fadmin", "/public/assets%2ffile",
		`/public\..\admin`, "/public/%5c../admin", "/public/%255c../admin",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if paths, valid := uri.RequestPaths(req); valid || paths != nil {
			t.Fatalf("ambiguous encoded separator accepted: %q", target)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/public/admin/%2e/../file", nil)
	paths, valid := uri.RequestPaths(req)
	if !valid || !slices.Contains(paths, "/public/admin/file") {
		t.Fatalf("escaped-path cleaning interpretation missing: %q, valid=%t", paths, valid)
	}
}

func TestRequestPathsUTF8(t *testing.T) {
	for _, target := range []string{
		"/public/%ff/file", "/public/%80/file", "/public/%EF%BF/file",
		"/public/%C0%AFadmin", "/public/%ED%A0%80/file", "/public/%F4%90%80%80/file",
		"/public/%ff/../file", "/public/%25ff/file", "/public/%2525ff/file",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			if paths, valid := uri.RequestPaths(req); valid || paths != nil {
				t.Fatalf("invalid UTF-8 accepted: Path=%q paths=%q", req.URL.Path, paths)
			}
		})
	}
	for _, target := range []string{"/public/%EF%BF%BD/file", "/caf%C3%A9/file", "/public/%F0%9F%94%92/file"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			paths, valid := uri.RequestPaths(req)
			if !valid || !slices.Contains(paths, req.URL.Path) {
				t.Fatal("valid Unicode path was rejected or changed")
			}
		})
	}
}
