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

package data

import (
	"strings"
)

// GetValueFromMapByPath returns value from map based on the key path.
func GetValueFromMapByPath(s string, m map[string]interface{}) interface{} {
	nm := m
	arr := strings.Split(s, "|")
	for i, k := range arr {
		if v, exists := nm[k]; exists {
			if i == (len(arr) - 1) {
				return v
			}
			switch vt := v.(type) {
			case map[string]interface{}:
				nm = vt
			default:
				return ""
			}
			continue
		}
		break
	}
	return ""
}
