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

// Package uri provides the shared request-path policy for authorization checks.
package uri

import (
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

// Bound additional decoding after net/http parses URL.Path.
const maxDecodePasses = 4

// RequestPaths returns every path interpretation produced by cleaning and up to
// four additional URL-decoding passes. Callers must authorize every result:
// neither cleaning nor decoding may grant access. Cleaning and decoding do not
// commute, so each decoding stage includes both the original and cleaned path,
// and both feed the next stage. It also checks cleaning EscapedPath before the
// initial decoding. Encoded slashes are rejected because segment-aware routers
// disagree with URL.Path about their segment boundaries.
//
// Mixed valid/invalid escapes, invalid UTF-8, and encodings remaining at the
// limit fail closed. UTF-8 is checked before cleaning at every decoding stage
// so regexp matching cannot alias malformed bytes to a literal U+FFFD path.
// Literal percent text without an encoded byte is terminal (e.g. "100%.txt").
// At most 124 interpretations are returned. Trailing slashes are preserved and
// the caller's request is never rewritten.
func RequestPaths(r *http.Request) ([]string, bool) {
	if r == nil || r.URL == nil {
		return nil, false
	}
	// Opaque targets, authority-form CONNECT, and OPTIONS * identify no URL path.
	// Never synthesize a root-path grant for these request targets. CONNECT
	// with a real path (e.g. net/rpc) still receives normal path checks.
	if r.URL.Opaque != "" || r.URL.Path == "*" || (r.Method == http.MethodConnect && r.URL.Path == "") {
		return nil, false
	}
	s := r.URL.Path
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	var paths []string
	pending := []string{s}
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, "/") {
		escaped = "/" + escaped
	}
	// Segment-aware routers retain escaped slashes as data, unlike URL.Path.
	// There is no unambiguous path grant for these different segment layouts.
	if strings.Contains(strings.ToLower(escaped), "%2f") {
		return nil, false
	}
	if escaped != s && strings.Contains(escaped, "%") {
		// A downstream router can clean EscapedPath before decoding it. This
		// order can retain a protected directory erased by cleaning URL.Path.
		cleaned := path.Clean(escaped)
		if strings.HasSuffix(escaped, "/") && cleaned != "/" {
			cleaned += "/"
		}
		decoded, err := url.PathUnescape(cleaned)
		if err != nil {
			return nil, false
		}
		pending = append(pending, decoded)
	}
	for pass := 0; len(pending) != 0; pass++ {
		var next []string
		for _, original := range pending {
			if !utf8.ValidString(original) {
				return nil, false
			}
			normalized := path.Clean(original)
			if strings.HasSuffix(original, "/") && normalized != "/" {
				normalized += "/"
			}
			for _, candidate := range []string{original, normalized} {
				if slices.Contains(paths, candidate) {
					continue
				}
				paths = append(paths, candidate)
				if !hasEncodedByte(candidate) {
					continue
				}
				if pass == maxDecodePasses {
					return nil, false
				}
				decoded, err := url.PathUnescape(candidate)
				if err != nil {
					return nil, false
				}
				next = append(next, decoded)
			}
		}
		pending = next
	}
	return paths, true
}

// A percent sign in URL.Path can be a decoded literal percent. Only complete
// %HH sequences admit another standard decoding interpretation. If these are
// mixed with malformed escapes, PathUnescape fails and the caller denies the
// request rather than trusting a path that a tolerant backend may decode.
func hasEncodedByte(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
			return true
		}
	}
	return false
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
