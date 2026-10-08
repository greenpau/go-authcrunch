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

package openapi

import (
	"fmt"
	"regexp"
	"strings"
)

var methods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true, "trace": true}
var pathParameter = regexp.MustCompile(`\{([^{}]+)\}`)
var responseCode = regexp.MustCompile(`^([1-5][0-9]{2}|[1-5]XX|default)$`)

// Validate checks authoring invariants in addition to ValidateStandard's
// OpenAPI structure and JSON Schema checks.
func Validate(doc map[string]any) error {
	if doc["openapi"] != "3.1.1" {
		return fmt.Errorf("expected OpenAPI 3.1.1")
	}
	for _, field := range []string{"title", "version", "description"} {
		if s, _ := object(doc["info"])[field].(string); strings.TrimSpace(s) == "" {
			return fmt.Errorf("info.%s must be a nonempty string", field)
		}
	}
	tags := map[string]bool{}
	for _, value := range array(doc["tags"]) {
		tag := object(value)
		name, _ := tag["name"].(string)
		if name == "" || tags[name] || tag["description"] == nil {
			return fmt.Errorf("invalid or duplicate tag %q", name)
		}
		tags[name] = true
	}
	paths := object(doc["paths"])
	if len(paths) == 0 {
		return fmt.Errorf("paths must not be empty")
	}
	ids := map[string]bool{}
	summaries := map[string]string{}
	pathCount := 0
	for path, value := range paths {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("invalid path %q", path)
		}
		pathCount++
		item := object(value)
		if _, override := item["servers"]; override {
			return fmt.Errorf("%s must inherit the document server; path server overrides bypass the shared mount", path)
		}
		operations := 0
		for method, value := range item {
			if !methods[method] {
				if method == "parameters" || method == "summary" || method == "description" || method == "servers" || strings.HasPrefix(method, "x-") {
					continue
				}
				return fmt.Errorf("unknown path item field %s at %s", method, path)
			}
			operations++
			op := object(value)
			if _, override := op["servers"]; override {
				return fmt.Errorf("%s %s must inherit the document server; operation server overrides bypass the shared mount", method, path)
			}
			id, _ := op["operationId"].(string)
			if id == "" || ids[id] {
				return fmt.Errorf("missing or duplicate operationId %q at %s %s", id, method, path)
			}
			ids[id] = true
			summary, _ := op["summary"].(string)
			label := strings.ToLower(strings.Join(strings.Fields(summary), " "))
			if label == "" {
				return fmt.Errorf("%s needs a nonempty summary", id)
			}
			location := fmt.Sprintf("%s %s (%s)", strings.ToUpper(method), path, id)
			if previous, exists := summaries[label]; exists {
				return fmt.Errorf("duplicate operation summary %q at %s; already used by %s", summary, location, previous)
			}
			summaries[label] = location
			if op["description"] == nil || len(array(op["tags"])) != 1 {
				return fmt.Errorf("%s needs a description and one tag", id)
			}
			tag, _ := array(op["tags"])[0].(string)
			if !tags[tag] {
				return fmt.Errorf("%s uses undeclared tag %q", id, tag)
			}
			if _, explicit := op["security"]; !explicit {
				return fmt.Errorf("%s must declare its credential boundary explicitly", id)
			}
			for _, requirement := range array(op["security"]) {
				for scheme := range object(requirement) {
					if object(object(doc["components"])["securitySchemes"])[scheme] == nil {
						return fmt.Errorf("%s uses unknown security scheme %s", id, scheme)
					}
				}
			}
			responses := object(op["responses"])
			if len(responses) == 0 {
				return fmt.Errorf("%s has no responses", id)
			}
			responseCount := 0
			for status, value := range responses {
				if strings.HasPrefix(status, "x-") {
					continue
				}
				if !responseCode.MatchString(status) {
					return fmt.Errorf("%s has invalid response code %q", id, status)
				}
				responseCount++
				response, err := dereference(doc, value)
				if err != nil {
					return err
				}
				if description, _ := object(response)["description"].(string); description == "" {
					return fmt.Errorf("%s response %s has no description", id, status)
				}
			}
			if responseCount == 0 {
				return fmt.Errorf("%s has no responses", id)
			}
			parameters := map[string]bool{}
			for _, scope := range []any{item["parameters"], op["parameters"]} {
				seen := map[string]bool{}
				for _, value := range array(scope) {
					value, err := dereference(doc, value)
					if err != nil {
						return err
					}
					parameter := object(value)
					name, _ := parameter["name"].(string)
					in, _ := parameter["in"].(string)
					if name == "" || seen[in+":"+name] {
						return fmt.Errorf("%s has an invalid or duplicate parameter %q", id, name)
					}
					seen[in+":"+name] = true
					if in == "path" {
						if parameter["required"] != true || !strings.Contains(path, "{"+name+"}") {
							return fmt.Errorf("%s has an invalid path parameter %s", id, name)
						}
						parameters[name] = true
					}
				}
			}
			for _, match := range pathParameter.FindAllStringSubmatch(path, -1) {
				if !parameters[match[1]] {
					return fmt.Errorf("%s is missing path parameter %s", id, match[1])
				}
			}
		}
		if operations == 0 {
			return fmt.Errorf("%s has no operations", path)
		}
	}
	if pathCount == 0 {
		return fmt.Errorf("paths must not be empty")
	}
	return walkReferences(doc, doc, documentKind)
}

func array(value any) []any {
	list, _ := value.([]any)
	return list
}

func dereference(doc map[string]any, value any) (any, error) {
	seen := map[string]bool{}
	for {
		ref, ok := object(value)["$ref"].(string)
		if !ok {
			return value, nil
		}
		if !strings.HasPrefix(ref, "#/") || seen[ref] {
			return nil, fmt.Errorf("invalid or cyclic reference %s", ref)
		}
		seen[ref] = true
		var err error
		value, err = pointer(doc, ref[1:])
		if err != nil {
			return nil, err
		}
	}
}

func walkReferences(doc map[string]any, value any, kind syntaxKind) error {
	if kind == literalKind {
		return nil
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "$ref" && kind.reference() {
				ref, ok := child.(string)
				if !ok || !strings.HasPrefix(ref, "#/components/") {
					return fmt.Errorf("unbundled reference %v", child)
				}
				if _, err := pointer(doc, ref[1:]); err != nil {
					return err
				}
			}
			if err := walkReferences(doc, child, kind.child(key)); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := walkReferences(doc, child, kind.child("")); err != nil {
				return err
			}
		}
	}
	return nil
}
