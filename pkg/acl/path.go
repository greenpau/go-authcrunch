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
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Bound retained patterns across users and tokens. Patterns beyond the cache
// capacity still receive the same authorization checks.
const maxCachedPathACLPatterns = 1024

var pathACLPatterns = struct {
	sync.RWMutex
	entries map[string]*regexp.Regexp
}{entries: make(map[string]*regexp.Regexp)}

// MatchPathBasedACL matches a literal path pattern with * and ** wildcards.
// A wildcard matches one or more ASCII letters, digits, underscore, dot, tilde,
// or hyphen; ** also spans slashes. All other pattern characters are literal.
// Patterns and paths must be valid UTF-8: regexp treats malformed bytes as
// U+FFFD, which would otherwise grant access to a different literal path.
func MatchPathBasedACL(pattern, uri string) bool {
	if pattern == "" || !utf8.ValidString(pattern) || !utf8.ValidString(uri) {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == uri
	}

	pathACLPatterns.RLock()
	regex, found := pathACLPatterns.entries[pattern]
	pathACLPatterns.RUnlock()
	if !found {
		// Quote before expanding wildcards. Regex punctuation in a path must
		// never expand a token's grant to a different resource or tenant.
		expression := regexp.QuoteMeta(pattern)
		expression = strings.ReplaceAll(expression, `\*\*`, "[a-zA-Z0-9_/.~-]+")
		expression = strings.ReplaceAll(expression, `\*`, "[a-zA-Z0-9_.~-]+")
		var err error
		regex, err = regexp.Compile("^" + expression + "$")
		if err != nil {
			return false
		}
		pathACLPatterns.Lock()
		if len(pathACLPatterns.entries) < maxCachedPathACLPatterns {
			pathACLPatterns.entries[pattern] = regex
		}
		pathACLPatterns.Unlock()
	}
	return regex.MatchString(uri)
}
