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

package accessclaims

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

type forbiddenMarshaler struct{ called *bool }

func (m forbiddenMarshaler) MarshalJSON() ([]byte, error) {
	*m.called = true
	return []byte(`"unsafe"`), nil
}
func TestAccessClaimsExactSnapshot(t *testing.T) {
	original := map[string]any{"integer": json.Number("9007199254740993"), "decimal": json.Number("0.12345678901234567890123456789"), "nested": map[string]any{"value": "before"}, "list": []string{"x"}}
	raw, snapshot, err := Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	original["nested"].(map[string]any)["value"] = "after"
	if snapshot["integer"] != json.Number("9007199254740993") || snapshot["nested"].(map[string]any)["value"] != "before" {
		t.Fatal("exact detached snapshot lost")
	}
	decoded, err := Decode(raw)
	if err != nil || !Equal(snapshot, decoded) {
		t.Fatal("exact round trip failed")
	}
	decoded["integer"] = json.Number("9007199254740992")
	if Equal(snapshot, decoded) {
		t.Fatal("adjacent large integers compared equal")
	}
}
func TestAccessClaimsRejectAmbiguousOrUnbounded(t *testing.T) {
	for name, raw := range map[string]string{"duplicate": `{"sub":"a","sub":"b"}`, "nested duplicate": `{"x":[{"a":1,"a":2}]}`, "second document": `{"x":1}{"y":2}`, "array": `[1]`, "empty": `{}`, "depth": `{"x":` + strings.Repeat(`[`, 16) + `1` + strings.Repeat(`]`, 16) + `}`, "long text": `{"x":"` + strings.Repeat("a", 4097) + `"}`, "too many nodes": `{"x":[` + strings.Repeat(`1,`, 4096) + `1]}`, "invalid UTF8": "{\"x\":\"" + string([]byte{255}) + "\"}"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(raw)); err == nil {
				t.Fatal("invalid document accepted")
			}
		})
	}
	called := false
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	for _, claims := range []map[string]any{{"x": forbiddenMarshaler{&called}}, {"x": math.NaN()}, {"x": math.Inf(1)}, {"x": json.Number("null")}, cycle} {
		if _, _, err := Encode(claims); err == nil {
			t.Fatal("unsupported claim accepted")
		}
	}
	if called {
		t.Fatal("custom marshaler invoked")
	}
}
func TestAccessClaimsReservedIntegers(t *testing.T) {
	for _, value := range []any{1, int64(1), uint64(1), float64(1), json.Number("1")} {
		if n, err := Integer(value); err != nil || n != 1 {
			t.Fatal("integral numeric input rejected")
		}
	}
	for _, value := range []any{"1", float64(1.5), json.Number("1.0"), json.Number("1e0"), json.Number("9223372036854775808"), uint64(math.MaxUint64), float64(math.MaxInt64), math.NaN(), nil} {
		if _, err := Integer(value); err == nil {
			t.Fatal("invalid reserved integer accepted")
		}
	}
}
