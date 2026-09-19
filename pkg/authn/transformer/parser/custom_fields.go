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
	"slices"
	"strings"
)

// ParseCustomFieldValues decodes the value body of an add-custom-field action:
// <value> as string, or <value> [<value> ...] as list/string_list/string list.
// Values are detached, literal template strings; only the runtime interpolates
// them against claims. Errors return no partial value and do not echo input.
// Directive and typed configuration compilation use this same decoder.
func ParseCustomFieldValues(args []string) (any, error) {
	values, kind, err := customFieldParts(args)
	if err != nil {
		return nil, err
	}
	return customFieldValue(values, kind)
}

// ParseCustomNestedFieldValues decodes <key> [<key> ...] with <values> as <type>,
// or <key> [<key> ...] as map. Scalar strings require one encoded value; lists
// require at least one. Nested values retain their established literal behavior.
// Returned paths and lists are detached; errors return no partial result.
func ParseCustomNestedFieldValues(args []string) ([]string, any, error) {
	parts, kind, err := customFieldParts(args)
	if err != nil {
		return nil, nil, err
	}
	split := slices.Index(parts, "with")
	if kind == "map" {
		if split >= 0 {
			return nil, nil, fmt.Errorf("map actions do not take values")
		}
		return slices.Clone(parts), map[string]any{}, nil
	}
	if split < 1 {
		return nil, nil, fmt.Errorf("nested actions require a path and with separator")
	}
	value, err := customFieldValue(parts[split+1:], kind)
	if err != nil {
		return nil, nil, err
	}
	return slices.Clone(parts[:split]), value, nil
}

func customFieldParts(args []string) ([]string, string, error) {
	if hasEmptyArgument(args) {
		return nil, "", fmt.Errorf("empty custom field argument")
	}
	split := slices.Index(args, "as")
	if split < 1 {
		return nil, "", fmt.Errorf("as type directive not found")
	}
	if split == len(args)-1 {
		return nil, "", fmt.Errorf("as type directive is too short")
	}
	kind := strings.Join(args[split+1:], "_")
	switch kind {
	case "string", "string_list", "list", "map":
		return args[:split], kind, nil
	default:
		return nil, "", fmt.Errorf("unsupported custom field type")
	}
}

func customFieldValue(values []string, kind string) (any, error) {
	switch kind {
	case "string":
		if len(values) != 1 {
			return nil, fmt.Errorf("string actions require one value")
		}
		return values[0], nil
	case "string_list", "list":
		if len(values) == 0 {
			return nil, fmt.Errorf("list actions require values")
		}
		return slices.Clone(values), nil
	default:
		return nil, fmt.Errorf("unsupported custom field type")
	}
}
