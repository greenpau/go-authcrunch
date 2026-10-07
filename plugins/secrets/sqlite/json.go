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

package sqlite

import (
	"encoding/json"
	"math"
	"unicode/utf8"
)

// Bound traversal before marshaling, rejecting lossy strings and Go values with
// implicit/custom serialization. The depth bound also terminates cyclic input.
func validSecretJSON(value any, depth int, nodes, text *int) bool {
	*nodes--
	if *nodes < 0 {
		return false
	}
	validString := func(s string) bool {
		*text -= len(s)
		return *text >= 0 && utf8.ValidString(s)
	}
	switch v := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case string:
		return validString(v)
	case json.Number:
		return len(v) > 0 && len(v) <= 128 && validString(string(v)) && json.Valid([]byte(v)) && (v[0] == '-' || v[0] >= '0' && v[0] <= '9')
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case float32:
		return !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0)
	case []string:
		if v == nil {
			return true
		}
		if depth >= 16 || len(v) > *nodes {
			return false
		}
		for _, item := range v {
			if !validSecretJSON(item, depth+1, nodes, text) {
				return false
			}
		}
	case []any:
		if v == nil {
			return true
		}
		if depth >= 16 || len(v) > *nodes {
			return false
		}
		for _, item := range v {
			if !validSecretJSON(item, depth+1, nodes, text) {
				return false
			}
		}
	case map[string]any:
		if v == nil {
			return true
		}
		if depth >= 16 || len(v) > *nodes {
			return false
		}
		for key, item := range v {
			if !validString(key) || !validSecretJSON(item, depth+1, nodes, text) {
				return false
			}
		}
	default:
		return false
	}
	return true
}
