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

package acl

import (
	"fmt"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestMatchPathBasedACL(t *testing.T) {
	testcases := []struct {
		name             string
		pattern          string
		matchedPaths     []string
		mismatchedPaths  []string
		wantMatchedFalse bool
	}{
		{
			name:    "match path based acl with max depth",
			pattern: "/*/media/**",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
				"/app/media/assets/icon.png",
				"/app/media/assets/images/icon.png",
			},
			mismatchedPaths: []string{
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
		{
			name:    "match path based acl with limited depth",
			pattern: "/*/media/*",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
			},
			mismatchedPaths: []string{
				"/app/media/assets/images/icon.png",
				"/app/media/assets/icon.png",
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
		{
			name:    "validate empty pattern",
			pattern: "",
			matchedPaths: []string{
				"/app/media/icon.png",
			},
			mismatchedPaths: []string{
				"/app/media/assets/images/icon.png",
			},
			wantMatchedFalse: true,
		},
		{
			name:    "validate exact match",
			pattern: "/app/media/icon.png",
			matchedPaths: []string{
				"/app/media/icon.png",
			},
		},
		{
			name:    "validate exact mismatch",
			pattern: "/app/media/icon.png",
			matchedPaths: []string{
				"/app/media/icon1.png",
			},
			wantMatchedFalse: true,
		},
		{
			name:    "literal punctuation does not match unrelated path",
			pattern: "(.*!",
			matchedPaths: []string{
				"/app/media/icon1.png",
			},
			wantMatchedFalse: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			want := make(map[string]any)
			got := make(map[string]any)
			for _, p := range tc.matchedPaths {
				if tc.wantMatchedFalse {
					want[p] = false
				} else {
					want[p] = true
				}
				got[p] = MatchPathBasedACL(tc.pattern, p)
			}
			for _, p := range tc.mismatchedPaths {
				want[p] = false
				got[p] = MatchPathBasedACL(tc.pattern, p)
			}
			tests.EvalObjects(t, "output", want, got)
		})
	}
}

func TestMatchPathBasedACLLiteralPatterns(t *testing.T) {
	for _, tc := range []struct{ pattern, allowed, denied string }{
		{"/tenant.v1/**", "/tenant.v1/file", "/tenantXv1/file"},
		{"/public/**|/admin", "/public/file|/admin", "/admin"},
		{"/public/(admin)/*", "/public/(admin)/file", "/public/admin/file"},
		{"/public/[ab]/*", "/public/[ab]/file", "/public/a/file"},
		{"/public/+/*", "/public/+/file", "/public///file"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			if !MatchPathBasedACL(tc.pattern, tc.allowed) {
				t.Error("literal pattern did not match its own path")
			}
			if MatchPathBasedACL(tc.pattern, tc.denied) {
				t.Error("literal pattern granted access through regex syntax")
			}
		})
	}
}

func TestMatchPathBasedACLConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 32 {
		wg.Go(func() {
			<-start
			pattern := fmt.Sprintf("/concurrent/%d/**", i)
			for range 20 {
				if !MatchPathBasedACL(pattern, fmt.Sprintf("/concurrent/%d/file", i)) {
					t.Error("allowed path rejected")
				}
				if MatchPathBasedACL(pattern, "/admin") {
					t.Error("protected path allowed")
				}
			}
		})
	}
	close(start)
	wg.Wait()
}

func TestMatchPathBasedACLCacheCapacity(t *testing.T) {
	for i := range maxCachedPathACLPatterns + 1 {
		pattern := fmt.Sprintf("/capacity/%d/*", i)
		if !MatchPathBasedACL(pattern, fmt.Sprintf("/capacity/%d/file", i)) {
			t.Fatal("cache capacity changed an allowed decision")
		}
		if MatchPathBasedACL(pattern, "/admin") {
			t.Fatal("cache capacity changed a denied decision")
		}
	}
	pathACLPatterns.RLock()
	size := len(pathACLPatterns.entries)
	pathACLPatterns.RUnlock()
	if size > maxCachedPathACLPatterns {
		t.Fatalf("cache grew to %d entries", size)
	}
}

func TestMatchPathBasedACLUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, value string
		want                 bool
	}{
		{"replacement character", "/tenant\uFFFD/**", "/tenant\uFFFD/file", true},
		{"invalid byte is not replacement character", "/tenant\uFFFD/**", "/tenant\xff/file", false},
		{"invalid continuation is not replacement character", "/tenant\uFFFD/**", "/tenant\x80/file", false},
		{"exact Unicode", "/tenant\uFFFD/file", "/tenant\uFFFD/file", true},
		{"invalid literal pattern", "/tenant\xff/file", "/tenant\xff/file", false},
		{"Unicode prefix", "/caf\u00e9/**", "/caf\u00e9/file", true},
		{"different Unicode normalization", "/caf\u00e9/**", "/cafe\u0301/file", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchPathBasedACL(tc.pattern, tc.value); got != tc.want {
				t.Fatalf("MatchPathBasedACL(%q, %q) = %t; want %t", tc.pattern, tc.value, got, tc.want)
			}
		})
	}
}

func FuzzMatchPathBasedACL(f *testing.F) {
	for _, seed := range [][2]string{
		{"/public/**", "/public/file"}, {"/public/*", "/public/a/b"},
		{"/tenant.v1/**", "/tenantXv1/file"}, {"/public/**|/admin", "/admin"},
		{"/tenant\uFFFD/**", "/tenant\xff/file"}, {"/tenant\uFFFD/**", "/tenant\uFFFD/file"},
		{`/public/\*`, `/public/\file`}, {"/public/***", "/public/a/b"},
		{"/public/(a)[b]+/*", "/public/(a)[b]+/file"}, {"/public/*", "/public/"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		// Bound the independent recursive model's work and retained cache data.
		if len(pattern) > 96 || len(value) > 96 {
			return
		}
		want := matchPathReference(pattern, value)
		if got := MatchPathBasedACL(pattern, value); got != want {
			t.Fatalf("MatchPathBasedACL(%q, %q) = %t; literal wildcard model wants %t", pattern, value, got, want)
		}
	})
}

// Model the documented literal/wildcard language without regex compilation,
// escaping, or the production cache. Memoization bounds repeated exploration.
func matchPathReference(pattern, value string) bool {
	if pattern == "" || !utf8.ValidString(pattern) || !utf8.ValidString(value) {
		return false
	}
	results := make(map[[2]int]bool)
	var match func(int, int) bool
	match = func(p, v int) (matched bool) {
		key := [2]int{p, v}
		if result, found := results[key]; found {
			return result
		}
		defer func() { results[key] = matched }()
		if p == len(pattern) {
			return v == len(value)
		}
		if pattern[p] != '*' {
			return v < len(value) && pattern[p] == value[v] && match(p+1, v+1)
		}
		p++
		spanSlashes := p < len(pattern) && pattern[p] == '*'
		if spanSlashes {
			p++
		}
		for v < len(value) {
			c := value[v]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_' || c == '.' || c == '~' ||
				c == '-' || (spanSlashes && c == '/')) {
				break
			}
			v++
			if match(p, v) {
				return true
			}
		}
		return false
	}
	return match(0, 0)
}
