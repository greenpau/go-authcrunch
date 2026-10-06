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

package enrichment_test

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
)

func TestJSONAttributeTypes(t *testing.T) {
	for _, value := range []any{
		nil, true, false, "", " whitespace\n\x00", json.Number("9007199254740993"),
		json.Number("1e999"), 42, int8(-1), int16(-2), int32(-3), int64(-4),
		uint(1), uint8(2), uint16(3), uint32(4), uint64(5), float32(1.5), float64(2.5),
		[]any{}, map[string]any{}, []string{},
		[]any{"read", nil, false, 1, map[string]any{"nested": []any{true}}},
	} {
		got, err := enrichment.CopyAttribute(value, "json")
		if err != nil || !reflect.DeepEqual(got, value) {
			t.Fatalf("JSON type %T was not preserved: %v", value, err)
		}
	}
	for _, value := range []any{[]any(nil), []string(nil), map[string]any(nil)} {
		if got, err := enrichment.CopyAttribute(value, "json"); err != nil || got != nil {
			t.Fatal("typed nil did not preserve JSON null semantics")
		}
	}
}

func TestJSONAttributeLimits(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	var deep any = "leaf"
	for range 16 {
		deep = []any{deep}
	}
	if _, err := enrichment.CopyAttribute(deep, "json"); err != nil {
		t.Fatal("maximum supported depth rejected")
	}
	if _, err := enrichment.CopyAttribute(make([]any, 4095), "json"); err != nil {
		t.Fatal("maximum supported node count rejected")
	}
	for _, value := range []any{
		cycle, []any{deep}, make([]any, 4096), make(chan int), func() {}, struct{}{},
		[]int{1}, map[int]string{1: "value"}, math.NaN(), math.Inf(1), float32(math.Inf(-1)),
		json.Number("true"), json.Number("null"), json.Number("01"), json.Number(""),
		json.Number("1 2"), json.Number("1e" + strings.Repeat("9", 128)),
		"\xff", strings.Repeat("x", 4097), map[string]any{"\xff": true},
		map[string]any{strings.Repeat("k", 4097): true},
		[]string{strings.Repeat("x", 4097)},
	} {
		if got, err := enrichment.CopyAttribute(value, "json"); got != nil || err == nil {
			t.Fatalf("invalid JSON type/size %T accepted", value)
		}
	}
	// Aggregate text and final escaped encoding each have a bound.
	for _, item := range []string{strings.Repeat("x", 4096), strings.Repeat("\x00", 4096)} {
		values := make([]any, 17)
		for i := range values {
			values[i] = item
		}
		if _, err := enrichment.CopyAttribute(values, "json"); err == nil {
			t.Fatal("aggregate JSON size limit ignored")
		}
	}
	if _, err := enrichment.CopyAttribute([]string{strings.Repeat("\x00", 4096), strings.Repeat("\x00", 4096), strings.Repeat("\x00", 4096)}, "json"); err == nil {
		t.Fatal("escaped encoded size limit ignored")
	}
}

func TestJSONNullAtDepthLimit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		leaf        any
		wantFailure bool
	}{
		{"null", nil, false},
		{"nil array", []any(nil), false},
		{"nil string array", []string(nil), false},
		{"nil object", map[string]any(nil), false},
		{"empty array", []any{}, true},
		{"empty string array", []string{}, true},
		{"empty object", map[string]any{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, objects := range []bool{false, true} {
				var value, want any = tc.leaf, nil
				for range 16 {
					if objects {
						value, want = map[string]any{"nested": value}, map[string]any{"nested": want}
					} else {
						value, want = []any{value}, []any{want}
					}
				}
				got, err := enrichment.CopyAttribute(value, "json")
				if tc.wantFailure {
					if err == nil || got != nil {
						t.Error("empty container was treated as a scalar null")
					}
				} else if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("JSON null at depth limit rejected or changed (objects=%t): %v", objects, err)
				}
				if got, err := enrichment.CopyAttribute([]any{value}, "json"); err == nil || got != nil {
					t.Error("null leaf bypassed the container depth limit")
				}
			}
		})
	}
}

func TestJSONEnrichmentIsolation(t *testing.T) {
	c := config()
	c.Attributes = []enrichment.AttributeConfig{{Name: "settings", Type: "json"}, {Name: "nothing", Type: "json"}}
	attributes := map[string]any{
		"settings": map[string]any{"enabled": true, "large": json.Number("9007199254740993"), "nested": []any{map[string]any{"value": "original"}}},
		"nothing":  nil,
	}
	e, err := enrichment.New(c, lookupFunc(func(_ context.Context, req enrichment.Request) (*enrichment.Result, error) {
		r := result(req)
		r.Attributes = attributes
		return r, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	original := identity(t)
	got, err := e.Enrich(t.Context(), original)
	if err != nil || !reflect.DeepEqual(got.AsMap()["settings"], attributes["settings"]) {
		t.Fatal("JSON claims did not reach the detached authorization identity", err)
	}
	if null, present := got.AsMap()["nothing"]; !present || null != nil {
		t.Fatal("JSON null was confused with an absent claim")
	}
	if _, present := original.AsMap()["settings"]; present {
		t.Fatal("caller was mutated")
	}
	attributes["settings"].(map[string]any)["nested"].([]any)[0].(map[string]any)["value"] = "changed"
	if got.AsMap()["settings"].(map[string]any)["nested"].([]any)[0].(map[string]any)["value"] != "original" {
		t.Fatal("nested backend result aliases decision data")
	}
}
