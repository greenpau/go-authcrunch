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

package parser

import (
	"fmt"
	"strconv"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Compile the provider-specific shorthand without changing the serialized
// matcher. The resulting ACL retains the same AND semantics as other matchers.
func compileGithubMatcher(args []string) (string, error) {
	if len(args) < 2 || args[0] != "match" || args[1] != "github" {
		return cfgutil.EncodeArgs(args), nil
	}
	if len(args) != 5 || (args[2] != "id" && args[2] != "org") {
		return "", fmt.Errorf("GitHub matcher requires id or org, an operator, and one value")
	}
	switch args[3] {
	case "exact":
		if args[2] == "org" {
			break
		}
		id, err := strconv.ParseUint(args[4], 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != args[4] {
			return "", fmt.Errorf("GitHub exact matcher requires a canonical positive integer")
		}
	case "regex":
		// The ACL constructor compiles and validates the expression once.
	default:
		return "", fmt.Errorf("unsupported GitHub match operator")
	}
	field := "github_id"
	if args[2] == "org" {
		field = "github_orgs"
	}
	return cfgutil.EncodeArgs([]string{args[3], "match", field, args[4]}), nil
}

func mutatesGithubClaims(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "add", "overwrite", "delete":
		field := args[1]
		if field == "nested" && len(args) > 2 {
			field = args[2]
		}
		return field == "github_id" || field == "github_orgs"
	}
	return false
}
