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
	"strings"
)

func sanitize(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range m {
		switch val := v.(type) {
		case string:
			out[k] = sanitizeStr(k, val)
		case map[string]interface{}:
			out[k] = sanitize(val)
		case []interface{}:
			var entries []string
			for _, entry := range val {
				switch s := entry.(type) {
				case string:
					entries = append(entries, sanitizeStr(k, s))
				}
			}
			if len(entries) > 0 {
				out[k] = entries
			} else {
				out[k] = v
			}
		default:
			out[k] = v
		}
	}
	return out
}

func sanitizeStr(k, s string) string {
	switch k {
	case "password", "secret", "old_password":
		return "***masked***"
	}
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	if len(s) > 255 {
		s = string(s[:254])
	}
	return s
}
