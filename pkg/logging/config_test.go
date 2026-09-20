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

package logging_test

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/logging"
)

func TestLoggingConfigValidation(t *testing.T) {
	for _, cfg := range []*logging.Config{
		nil,
		{Skip: []logging.SkipRule{{Text: "noise"}}},
		{Skip: []logging.SkipRule{{Match: "invalid", Text: "noise"}}},
		{Skip: []logging.SkipRule{{Match: "exact"}}},
		{Skip: []logging.SkipRule{{Match: "partial", Text: "\t "}}},
		{Skip: []logging.SkipRule{{Match: "partial", Text: "line\nnext"}}},
		{Skip: []logging.SkipRule{{Match: "partial", Text: "\xff"}}},
		{Skip: []logging.SkipRule{{Match: "regex", Text: "["}}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid typed config validated")
		}
		if cfg != nil {
			if filter, err := logging.NewFilter(cfg); filter != nil || err == nil {
				t.Fatal("invalid typed config created filter")
			}
		}
	}
	for _, cfg := range []*logging.Config{nil, {}} {
		filter, err := logging.NewFilter(cfg)
		if err != nil || filter.ShouldSkip("anything") {
			t.Fatal("omitted or empty config suppressed output")
		}
	}
}

func TestLoggingConfigSnapshotAndSerialization(t *testing.T) {
	cfg := &logging.Config{Skip: []logging.SkipRule{{Match: "regex", Text: "^old$"}}}
	original, err := logging.NewFilter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Skip[0].Text = "^new$"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, codec := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"json", json.Marshal, json.Unmarshal},
		{"xml", xml.Marshal, xml.Unmarshal},
		{"yaml", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(codec.name, func(t *testing.T) {
			data, err := codec.marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var restored logging.Config
			if err := codec.unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.Skip, cfg.Skip) {
				t.Fatal("serialized rules changed")
			}
			filter, err := logging.NewFilter(&restored)
			if err != nil {
				t.Fatal(err)
			}
			if !original.ShouldSkip("old") || original.ShouldSkip("new") || !filter.ShouldSkip("new") || filter.ShouldSkip("old") {
				t.Fatal("snapshot or restored matching changed")
			}
		})
	}
	cfg.Skip[0].Text = "["
	if _, err := logging.NewFilter(cfg); err == nil {
		t.Fatal("stale validation accepted invalid replacement")
	}
}
