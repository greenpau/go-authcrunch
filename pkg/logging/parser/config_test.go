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

package parser_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/logging"
	"github.com/greenpau/go-authcrunch/pkg/logging/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewLoggingConfigFromDirectives(t *testing.T) {
	for _, matcher := range []string{"exact", "partial", "prefix", "suffix", "regex"} {
		t.Run(matcher, func(t *testing.T) {
			value := `reason: no token found, "tenant Ω" \d+`
			statements := []string{cfgutil.EncodeArgs([]string{"skip", matcher, "text", value})}
			before := append([]string(nil), statements...)
			cfg, err := parser.NewLoggingConfigFromDirectives(statements)
			if err != nil || cfg == nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(cfg.Skip, []logging.SkipRule{{Match: matcher, Text: value}}) || !reflect.DeepEqual(statements, before) {
				t.Fatal("parser changed tokens or input")
			}
		})
	}
	for _, statements := range [][]string{nil, {}, {`skip partial text noise`, `skip partial text noise`}} {
		cfg, err := parser.NewLoggingConfigFromDirectives(statements)
		if err != nil || len(cfg.Skip) != len(statements) {
			t.Fatalf("empty or repeated rules: %v", err)
		}
	}
}

func TestLoggingDirectiveRejections(t *testing.T) {
	for i, statement := range []string{
		"", " ", "skip", "skip text noise", "skip partial text", "skip partial text noise extra",
		"logging {", "}", "allow partial text noise", "skip partial message noise",
		"skip unknown text noise", "skip Partial text noise", `skip partial text ""`,
		`skip partial text "   "`, `skip regex text "["`, `skip partial text "unterminated`,
		"skip partial text noise\nskip exact text more", "skip partial text noise\r",
		cfgutil.EncodeArgs([]string{"skip", "partial", "text", "noise\nmore"}),
		"skip partial text \xff", `skip  partial text noise`,
	} {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			cfg, err := parser.NewLoggingConfigFromDirectives([]string{"skip exact text accepted", statement})
			if cfg != nil || err == nil {
				t.Fatal("invalid directive returned partial or successful config")
			}
			if strings.Contains(err.Error(), "noise") || strings.Contains(err.Error(), "unknown") {
				t.Fatal("error echoed input")
			}
		})
	}
}

func ExampleNewLoggingConfigFromDirectives() {
	config, err := parser.NewLoggingConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"skip", "partial", "text", "auth provider returned error"}),
		cfgutil.EncodeArgs([]string{"skip", "partial", "text", "reason: no token found"}),
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	data, _ := json.Marshal(config)
	fmt.Println(string(data))
	// Output: {"skip":[{"match":"partial","text":"auth provider returned error"},{"match":"partial","text":"reason: no token found"}]}
}
