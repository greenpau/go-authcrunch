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
	i, exists := m["path"]
	if !exists {
		return m
	}

	out := make(map[string]interface{})
	for k, v := range m {
		switch k {
		case "path":
			switch v := i.(type) {
			case string:
				s := strings.ReplaceAll(v, "\n", "")
				s = strings.ReplaceAll(s, "\r", "")
				if len(s) > 255 {
					s = s[:254]
				}
				out[k] = s
			}
		default:
			out[k] = v
		}
	}
	return out
}
