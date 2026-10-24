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

// Package accessclaims owns the bounded exact JSON envelope shared by access
// issuers and verifiers. It does not authenticate or authorize claims.
package accessclaims

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// Encode returns an independent JSON snapshot without invoking custom marshalers.
// It validates before encoding to bound allocation and reject custom marshalers.
// Decode the bounded serialized snapshot for policy checks so the checked claims
// are exactly the claims signed, including precise json.Number values.
func Encode(claims map[string]any) ([]byte, map[string]any, error) {
	invalid := func() ([]byte, map[string]any, error) {
		return nil, nil, fmt.Errorf("access claims have invalid JSON type or size")
	}
	nodes, text := 4096, 64<<10
	if len(claims) == 0 || len(claims) > 128 || !validJSON(claims, 0, &nodes, &text) {
		return invalid()
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > 64<<10 {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var snapshot map[string]any
	if decoder.Decode(&snapshot) != nil {
		return invalid()
	}
	return payload, snapshot, nil
}

func validJSON(value any, depth int, nodes, text *int) bool {
	*nodes--
	if *nodes < 0 {
		return false
	}
	validString := func(s string) bool {
		*text -= len(s)
		return *text >= 0 && len(s) <= 4096 && utf8.ValidString(s)
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
			if !validJSON(item, depth+1, nodes, text) {
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
			if !validJSON(item, depth+1, nodes, text) {
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
			if !validString(key) || !validJSON(item, depth+1, nodes, text) {
				return false
			}
		}
	default:
		return false
	}
	return true
}

// Decode reads one bounded object, rejecting duplicate members at every level.
// JSON numbers retain their exact source representation.
func Decode(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > 64<<10 || !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid access JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes, text := 4096, 64<<10
	value, err := readValue(decoder, 0, &nodes, &text)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid access JSON")
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 || len(object) > 128 {
		return nil, fmt.Errorf("invalid access JSON object")
	}
	return object, nil
}
func readValue(d *json.Decoder, depth int, nodes, text *int) (any, error) {
	*nodes--
	if *nodes < 0 || depth > 16 {
		return nil, fmt.Errorf("access JSON limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid access JSON")
	}
	checkString := func(s string) bool { *text -= len(s); return len(s) <= 4096 && *text >= 0 }
	switch value := token.(type) {
	case json.Delim:
		if depth >= 16 {
			return nil, fmt.Errorf("access JSON depth exceeded")
		}
		switch value {
		case '{':
			object := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || !checkString(name) {
					return nil, fmt.Errorf("invalid access JSON member")
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("duplicate access JSON member")
				}
				item, err := readValue(d, depth+1, nodes, text)
				if err != nil {
					return nil, err
				}
				object[name] = item
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("invalid access JSON object")
			}
			return object, nil
		case '[':
			values := make([]any, 0)
			for d.More() {
				item, err := readValue(d, depth+1, nodes, text)
				if err != nil {
					return nil, err
				}
				values = append(values, item)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("invalid access JSON array")
			}
			return values, nil
		}
	case string:
		if checkString(value) {
			return value, nil
		}
	case json.Number:
		if len(value) <= 128 && checkString(string(value)) {
			return value, nil
		}
	case nil, bool:
		return value, nil
	}
	return nil, fmt.Errorf("invalid access JSON value")
}

// Equal compares exact canonical JSON, retaining json.Number precision.
func Equal(first, second map[string]any) bool {
	a, _, err := Encode(first)
	if err != nil {
		return false
	}
	b, _, err := Encode(second)
	return err == nil && bytes.Equal(a, b)
}

// Integer accepts only lossless integral JSON values representable in int64.
func Integer(value any) (int64, error) {
	switch n := value.(type) {
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case uint:
		if uint64(n) <= math.MaxInt64 {
			return int64(n), nil
		}
	case uint8:
		return int64(n), nil
	case uint16:
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), nil
		}
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n >= math.MinInt64 && n < math.MaxInt64 && math.Trunc(n) == n {
			return int64(n), nil
		}
	case float32:
		return Integer(float64(n))
	case json.Number:
		if len(n) > 0 && len(n) <= 128 {
			if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("access time must be an exact integer")
}
