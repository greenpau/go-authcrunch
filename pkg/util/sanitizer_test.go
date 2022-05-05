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

package util

import (
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
)

func TestSanitizeURL(t *testing.T) {
	t.Run("should sanitize  url if its malformed in a way that is intended to cause a XSS", func(t *testing.T) {
		maliciousURL := "https://www.google.com/search?hl=en&q=testing'\"()&%<acx><ScRiPt >alert(9854)</ScRiPt>"
		sanitizedURL := SanitizeURL(maliciousURL)
		tests.EvalObjectsWithLog(t,
			"sanitized url",
			"https://www.google.com/search?hl=en%26q=testing%27%22()%26%%3Cacx%3E%3CScRiPt %3Ealert(9854)%3C/ScRiPt%3E",
			sanitizedURL,
			[]string{},
		)
	})
}
