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

package enrichment

import (
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

// copyJSON accepts encoding/json data shapes, native numeric scalars and
// []string. Explicit recursion bounds reject cycles without reflection.
func copyJSON(value any) (any, error) {
	remaining, textBytes := 4096, 64<<10
	out, err := copyJSONValue(value, 0, &remaining, &textBytes)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > 64<<10 {
		return nil, fmt.Errorf("claims enrichment JSON value exceeds encoding limits")
	}
	return out, nil
}

func copyJSONValue(value any, depth int, remaining, textBytes *int) (any, error) {
	invalid := func() (any, error) { return nil, fmt.Errorf("claims enrichment JSON value has invalid type or size") }
	*remaining--
	if *remaining < 0 {
		return invalid()
	}
	switch v := value.(type) {
	case nil, bool:
		return v, nil
	case string:
		*textBytes -= len(v)
		if *textBytes < 0 || len(v) > 4096 || !utf8.ValidString(v) {
			return invalid()
		}
		return v, nil
	case json.Number:
		if len(v) == 0 || len(v) > 128 || !json.Valid([]byte(v)) || (v[0] != '-' && (v[0] < '0' || v[0] > '9')) {
			return invalid()
		}
		return v, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return invalid()
		}
		return v, nil
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return invalid()
		}
		return v, nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return v, nil
	case []string:
		// A typed nil encodes as a scalar null, not another container level.
		if v == nil {
			return nil, nil
		}
		if depth >= 16 || len(v) > *remaining {
			return invalid()
		}
		out := make([]string, len(v))
		for i, item := range v {
			copied, err := copyJSONValue(item, depth+1, remaining, textBytes)
			if err != nil {
				return nil, err
			}
			out[i] = copied.(string)
		}
		return out, nil
	case []any:
		if v == nil {
			return nil, nil
		}
		if depth >= 16 || len(v) > *remaining {
			return invalid()
		}
		out := make([]any, len(v))
		for i, item := range v {
			copied, err := copyJSONValue(item, depth+1, remaining, textBytes)
			if err != nil {
				return nil, err
			}
			out[i] = copied
		}
		return out, nil
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		if depth >= 16 || len(v) > *remaining {
			return invalid()
		}
		out := make(map[string]any, len(v))
		for key, item := range v {
			*textBytes -= len(key)
			if *textBytes < 0 || len(key) > 4096 || !utf8.ValidString(key) {
				return invalid()
			}
			copied, err := copyJSONValue(item, depth+1, remaining, textBytes)
			if err != nil {
				return nil, err
			}
			out[key] = copied
		}
		return out, nil
	default:
		return invalid()
	}
}
