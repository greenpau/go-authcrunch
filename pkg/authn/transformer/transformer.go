// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package transformer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/config"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Config preserves the serialized transform configuration shared with parser.
type Config = config.Config

type transform struct {
	matcher        *acl.AccessList
	actions        [][]string
	challengeRules *authchal.Ruleset
}

// Factory applies an ordered, immutable snapshot of user transformations.
type Factory struct {
	transforms []*transform
}

// NewFactory validates and snapshots matcher/action configuration.
func NewFactory(cfgs []*Config) (*Factory, error) {
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("transformer has no config")
	}
	f := &Factory{}
	for _, cfg := range cfgs {
		compiled, err := parser.CompileUserTransformerConfig(cfg)
		if err != nil {
			return nil, err
		}
		f.transforms = append(f.transforms, &transform{matcher: compiled.Matcher, actions: compiled.Actions, challengeRules: compiled.AuthenticationChallenges})
	}
	return f, nil
}

// ErrAuthChallengesUnavailable means no matched policy can be satisfied by the
// identified backend's registered methods. It must never fall back to defaults.
var ErrAuthChallengesUnavailable = errors.New("no authentication challenge rule matches registered methods")

// Transform performs claim transformations. Callers using authentication policy
// supply a server-owned []string under auth_methods; it is consumed, never issued.
// Portal integrations should prefer TransformWithAuthMethods to separate evidence
// from claims. Selected challenges precede additive legacy requirements here.
func (f *Factory) Transform(m map[string]any) error {
	methods, _ := m["auth_methods"].([]string)
	selected, err := f.TransformWithAuthMethods(m, methods)
	if err != nil {
		return err
	}
	if selected != nil {
		additional, _ := m["challenges"].([]string)
		m["challenges"] = append(selected, additional...)
	}
	return nil
}

// TransformWithAuthMethods transforms claims and returns a replacement backend
// challenge sequence, or nil when no matching transform declares such a policy.
// Legacy require actions remain additive in m["challenges"]. The first eligible
// rule across matching transforms wins; later claim and deny actions still run.
// Registered methods must come from the backend, never JWT or client claims.
func (f *Factory) TransformWithAuthMethods(m map[string]any, methods []string) ([]string, error) {
	if m == nil {
		return nil, fmt.Errorf("nil transformer claims")
	}
	registered := make(map[string]bool, len(methods))
	for _, method := range methods {
		// The portal has no email checkpoint implementation.
		if method != authchal.EmailKeyword {
			registered[method] = true
		}
	}
	delete(m, "auth_methods")
	delete(m, "challenges")
	defer delete(m, "auth_methods")
	var selected, challenges, frontendLinks []string
	var policySeen bool
	if mail, exists := m["mail"]; exists {
		value, ok := mail.(string)
		if !ok {
			return nil, fmt.Errorf("invalid mail claim")
		}
		m["email"] = value
		delete(m, "mail")
	}
	for _, transform := range f.transforms {
		if !transform.matcher.Allow(context.Background(), m) {
			continue
		}
		if transform.challengeRules != nil {
			policySeen = true
			if selected == nil && len(methods) > 0 {
				selected = transform.challengeRules.ResolveChallenges(registered)
			}
		}
		for _, args := range transform.actions {
			switch args[0] {
			case "block", "deny":
				return nil, fmt.Errorf("transformer action is block/deny")
			case "require":
				if len(args) >= 3 && args[1] == "auth" && args[2] == "challenges" {
					continue
				}
				challenges = append(challenges, cfgutil.EncodeArgs(args[1:]))
			case "link":
				frontendLinks = append(frontendLinks, cfgutil.EncodeArgs(args[1:]))
			default:
				if err := transformData(args, m, transform.matcher); err != nil {
					return nil, fmt.Errorf("transformer action failed: %w", err)
				}
			}
		}
	}
	if policySeen && selected == nil {
		return nil, ErrAuthChallengesUnavailable
	}
	// Only require actions may create challenge policy. Custom claims cannot inject it.
	delete(m, "challenges")
	if len(challenges) > 0 {
		m["challenges"] = challenges
	}
	if len(frontendLinks) > 0 {
		m["frontend_links"] = frontendLinks
	}
	return selected, nil
}

func transformData(args []string, m map[string]interface{}, matcher *acl.AccessList) error {
	if len(args) == 2 && args[0] == "delete" {
		field, _ := acl.GetFieldDataType(args[1])
		delete(m, field)
		return nil
	}
	if len(args) < 3 {
		return fmt.Errorf("too short")
	}
	switch args[0] {
	case "add", "delete", "overwrite", "drop":
	default:
		return fmt.Errorf("unsupported action %v", args[0])
	}

	k, dt := acl.GetFieldDataType(args[1])
	switch args[0] {
	case "add":
		switch dt {
		case "list_str":
			var entries, newEntries []string
			switch val := m[k].(type) {
			case string:
				entries = strings.Split(val, " ")
			case []string:
				entries = val
			case []interface{}:
				for _, entry := range val {
					switch e := entry.(type) {
					case string:
						entries = append(entries, e)
					}
				}
			case nil:
			default:
				return fmt.Errorf("unsupported %q field type %T with value: %v in %v", k, val, val, args)
			}
			existing := len(entries)
			entries = append(entries, args[2:]...)
			entryMap := make(map[string]bool)
			for i, e := range entries {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				v := e
				if i >= existing {
					var err error
					v, err = repl(m, e)
					if err != nil {
						return err
					}
				}
				if _, exists := entryMap[v]; exists {
					continue
				}
				entryMap[v] = true
				newEntries = append(newEntries, v)
			}
			m[k] = newEntries
		case "str":
			// Existing claim text is data; only configured additions are templates.
			v, err := repl(m, strings.Join(args[2:], " "))
			if err != nil {
				return err
			}
			if current, ok := m[k].(string); ok {
				v = current + " " + v
			}
			m[k] = v
		default:
			// Handle custom fields.
			if args[1] == "nested" {
				nestedKeys, nestedValues, err := parser.ParseCustomNestedFieldValues(args[2:])
				if err != nil {
					return fmt.Errorf("failed transforming %q field for %q action in %v: %v", k, args[0], args, err)
				}

				mp := m
				for i, v := range nestedKeys {
					if i == len(nestedKeys)-1 {
						// Handle last element.
						mp[v] = nestedValues
						continue
					}
					mv, exists := mp[v]
					if !exists {
						next := make(map[string]any)
						mp[v] = next
						mp = next
						continue
					}
					next, ok := mv.(map[string]any)
					if !ok || next == nil {
						return fmt.Errorf("nested claim parent must be an object")
					}
					mp = next
				}
				break
			}
			v, err := parseCustomFieldValues(m, args[2:])
			if err != nil {
				return fmt.Errorf("failed transforming %q field for %q action in %v: %v", k, args[0], args, err)
			}
			m[args[1]] = v
		}
	case "overwrite":
		switch dt {
		case "list_str":
			m[k] = append([]string{}, args[2:]...)
		case "str":
			m[k] = strings.Join(args[2:], " ")
		default:
			return fmt.Errorf("unsupported %q field for %q action in %v", k, args[0], args)
		}
	case "drop":
		if len(args) != 3 {
			return fmt.Errorf("malformed %q action in %v", args[0], args)
		}
		if args[1] != "matched" || args[2] != "role" {
			return fmt.Errorf("malformed %q action in %v", args[0], args)
		}

		if args[1] == "matched" && args[2] == "role" {
			if _, exists := m["roles"]; exists {
				var entries, newEntries []string
				switch val := m["roles"].(type) {
				case []string:
					entries = val
				case []interface{}:
					for _, entry := range val {
						switch e := entry.(type) {
						case string:
							entries = append(entries, e)
						}
						return fmt.Errorf("failed to %q action in %v due to unsupported data type inside the input data", args[0], args)
					}
				default:
					return fmt.Errorf("failed to %q action in %v due to unsupported data type inside the input data", args[0], args)
				}

				for _, e := range entries {
					em := map[string]interface{}{
						"roles": []string{e},
					}
					if matched := matcher.Allow(context.Background(), em); matched {
						continue
					}
					newEntries = append(newEntries, e)

				}
				m["roles"] = newEntries
			}
		}
	default:
		return fmt.Errorf("unsupported %q action in %v", args[0], args)
	}
	return nil
}

func parseCustomFieldValues(m map[string]any, args []string) (any, error) {
	raw, err := parser.ParseCustomFieldValues(args)
	if err != nil {
		return nil, err
	}
	switch value := raw.(type) {
	case string:
		return repl(m, value)
	case []string:
		return replArr(m, value)
	default:
		return nil, fmt.Errorf("unsupported custom field value")
	}
}

func getReplValue(m map[string]interface{}, s string) (string, error) {
	var value string
	v, exists := m[s]
	if !exists {
		return value, fmt.Errorf("transform replace field %q not found", s)
	}
	switch val := v.(type) {
	case string:
		value = val
	default:
		return "", fmt.Errorf("transform replace field %q value type %T is unsupported", s, val)
	}
	return value, nil
}

// repl expands only placeholders in the configured template. Claim values are
// written literally, so recursive references cannot loop or become instructions.
func repl(m map[string]any, template string) (string, error) {
	var out strings.Builder
	for {
		start := strings.IndexByte(template, '{')
		if start < 0 {
			out.WriteString(template)
			return out.String(), nil
		}
		end := strings.IndexByte(template[start:], '}')
		if end < 0 {
			out.WriteString(template)
			return out.String(), nil
		}
		end += start
		pattern := template[start : end+1]
		if !strings.HasPrefix(pattern, "{claims.") {
			return "", fmt.Errorf("unsupported transform replacement pattern")
		}
		key := pattern[len("{claims.") : len(pattern)-1]
		if key == "" || strings.ContainsAny(key, "{}") {
			return "", fmt.Errorf("invalid transform replacement field")
		}
		value, err := getReplValue(m, key)
		if err != nil {
			return "", err
		}
		out.WriteString(template[:start])
		out.WriteString(value)
		template = template[end+1:]
	}
}

func replArr(m map[string]interface{}, arr []string) ([]string, error) {
	var values []string
	for _, s := range arr {
		value, err := repl(m, s)
		if err != nil {
			return values, err
		}
		values = append(values, value)
	}
	return values, nil
}
