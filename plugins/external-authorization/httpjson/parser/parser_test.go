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
	"fmt"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson/parser"
)

func TestHTTPJSONParser(t *testing.T) {
	c, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint https://policy.test/decide", "timeout 250ms"})
	if err != nil || c.Endpoint != "https://policy.test/decide" || c.Timeout != "250ms" {
		t.Fatal("parser lost configuration")
	}
	for _, bad := range []string{"", "unknown canary", "endpoint https://duplicate.test", "timeout 31s", "timeout", "timeout 1s extra", "timeout \xff", "timeout 1s\ncanary", `timeout ""`, `timeout "unterminated`} {
		c, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint https://policy.test/decide", bad})
		if err == nil || c != nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("invalid directive accepted or disclosed")
		}
	}
	if c, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives(nil); c != nil || err == nil {
		t.Fatal("empty block accepted")
	}
}
func ExampleNewHTTPJSONAuthorizerConfigFromDirectives() {
	c, err := parser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint https://policy.test/decide"})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Endpoint, c.Timeout)
	// Output: https://policy.test/decide 1s
}
