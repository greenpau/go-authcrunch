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
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strings"
)

// Config represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type Config struct {
	Matchers []string `json:"matchers,omitempty" xml:"matchers,omitempty" yaml:"matchers,omitempty"`
	Actions  []string `json:"actions,omitempty" xml:"actions,omitempty" yaml:"actions,omitempty"`
}

type transform struct {
	matcher *acl.AccessList
	actions [][]string
}

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	configs    []*Config
	transforms []*transform
}

// NewFactory returns an instance of cookie factory.
func NewFactory(cfgs []*Config) (*Factory, error) {
	f := &Factory{}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("transformer has no config")
	}
	f.configs = cfgs

	for _, cfg := range cfgs {
		if len(cfg.Matchers) < 1 {
			return nil, fmt.Errorf("transformer has no matchers: %v", cfg)
		}
		if len(cfg.Actions) < 1 {
			return nil, fmt.Errorf("transformer has no actions: %v", cfg)
		}

		var actions [][]string
		for _, encodedArgs := range cfg.Actions {
			args, err := cfgutil.DecodeArgs(encodedArgs)
			if err != nil {
				return nil, fmt.Errorf("transformer for %q erred during arg decoding: %v", encodedArgs, err)
			}
			switch args[0] {
			case "require":
				actions = append(actions, args)
			case "block", "deny":
				actions = append(actions, args)
			case "ui":
				if len(args) < 4 {
					return nil, fmt.Errorf("transformer for %q erred: ui config too short", encodedArgs)
				}
				switch args[1] {
				case "link":
					actions = append(actions, args[1:])
				default:
					return nil, fmt.Errorf("transformer for %q erred: invalid ui config", encodedArgs)
				}
			case "add", "overwrite":
				if len(args) < 3 {
					return nil, fmt.Errorf("transformer for %q erred: invalid add/overwrite config", encodedArgs)
				}
				actions = append(actions, args)
			case "delete":
				if len(args) < 2 {
					return nil, fmt.Errorf("transformer for %q erred: invalid delete config", encodedArgs)
				}
				actions = append(actions, args)
			case "action":
				if len(args) < 3 {
					return nil, fmt.Errorf("transformer for %q erred: action config too short", encodedArgs)
				}
				switch args[1] {
				case "add", "overwrite", "delete":
				default:
					return nil, fmt.Errorf("transformer for %q erred: invalid action config", encodedArgs)
				}
				actions = append(actions, args[1:])
			default:
				return nil, fmt.Errorf("transformer has unsupported action: %v", args)
			}
		}
		matcher := acl.NewAccessList()
		matchRuleConfigs := []*acl.RuleConfiguration{
			{
				Conditions: cfg.Matchers,
				Action:     "allow",
			},
		}
		if err := matcher.AddRules(context.Background(), matchRuleConfigs); err != nil {
			return nil, err
		}
		tr := &transform{
			matcher: matcher,
			actions: actions,
		}
		f.transforms = append(f.transforms, tr)
	}
	return f, nil
}

// Transform performs user data transformation.
func (f *Factory) Transform(m map[string]interface{}) error {
	var challenges, frontendLinks []string
	if _, exists := m["mail"]; exists {
		m["email"] = m["mail"].(string)
		delete(m, "mail")
	}
	for _, transform := range f.transforms {
		if matched := transform.matcher.Allow(context.Background(), m); !matched {
			continue
		}
		for _, args := range transform.actions {
			switch args[0] {
			case "block", "deny":
				return fmt.Errorf("transformer action is block/deny")
			case "require":
				challenges = append(challenges, cfgutil.EncodeArgs(args[1:]))
			case "link":
				frontendLinks = append(frontendLinks, cfgutil.EncodeArgs(args[1:]))
			default:
				if err := transformData(args, m); err != nil {
					return fmt.Errorf("transformer for %v erred: %v", args, err)
				}
			}
		}
	}
	if len(challenges) > 0 {
		m["challenges"] = challenges
	}
	if len(frontendLinks) > 0 {
		m["frontend_links"] = frontendLinks
	}
	return nil
}

func transformData(args []string, m map[string]interface{}) error {
	if len(args) < 3 {
		return fmt.Errorf("too short")
	}
	switch args[0] {
	case "add", "delete", "overwrite":
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
			entries = append(entries, args[2:]...)
			entryMap := make(map[string]bool)
			for _, e := range entries {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				v, err := repl(m, e)
				if err != nil {
					return err
				}
				if _, exists := entryMap[v]; exists {
					continue
				}
				entryMap[v] = true
				newEntries = append(newEntries, v)
			}
			m[k] = newEntries
		case "str":
			var e string
			switch val := m[k].(type) {
			case string:
				e = val + " " + strings.Join(args[2:], " ")
			case nil:
				e = strings.Join(args[2:], " ")
			}

			v, err := repl(m, e)
			if err != nil {
				return err
			}
			m[k] = v
		default:
			// Handle custom fields.
			if args[1] == "nested" {
				nestedKeys, nestedValues, err := parseCustomNestedFieldValues(args[2:])
				if err != nil {
					return fmt.Errorf("failed transforming %q field for %q action in %v: %v", k, args[0], args, err)
				}

				// Use pointers to create nested map.
				var mp map[string]interface{}
				mp = m
				for i, v := range nestedKeys {
					if i == len(nestedKeys)-1 {
						// Handle last element.
						mp[v] = nestedValues
						continue
					}
					mv, exists := mp[v]
					if !exists {
						mp[v] = make(map[string]interface{})
						mp = mp[v].(map[string]interface{})
						continue
					}
					mp = mv.(map[string]interface{})
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
	default:
		return fmt.Errorf("unsupported %q action in %v", args[0], args)
	}
	return nil
}

func parseCustomFieldValues(m map[string]interface{}, args []string) (interface{}, error) {
	var x int
	for i, arg := range args {
		if arg == "as" {
			x = i
			break
		}
	}
	if x == 0 {
		return nil, fmt.Errorf("as type directive not found")
	}
	if len(args[x:]) < 2 {
		return nil, fmt.Errorf("as type directive is too short")
	}
	dt := strings.Join(args[x+1:], "_")
	switch dt {
	case "string_list", "list":
		values, err := replArr(m, args[:x])
		if err != nil {
			return nil, err
		}
		return values, nil
	case "string":
		value, err := repl(m, args[x-1])
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	return nil, fmt.Errorf("unsupported %q data type", dt)
}

func parseCustomNestedFieldValues(args []string) ([]string, interface{}, error) {
	var x, y int
	for i, arg := range args {
		if arg == "with" {
			y = i
		}
		if arg == "as" {
			x = i
			break
		}
	}
	if x == 0 {
		return nil, nil, fmt.Errorf("as type directive not found")
	}
	if len(args[x:]) < 2 {
		return nil, nil, fmt.Errorf("as type directive is too short")
	}

	dt := strings.Join(args[x+1:], "_")
	args = args[:x]

	if (dt != "map") && (y < 1) {
		return nil, nil, fmt.Errorf("the with keyword not found")
	}

	switch dt {
	case "string_list", "list":
		return args[:y], args[y+1:], nil
	case "string":
		return args[:y], args[y+1], nil
	case "map":
		m := make(map[string]interface{})
		return args, m, nil
	}
	return nil, nil, fmt.Errorf("unsupported %q data type", dt)
}

func hasReplPattern(s string) bool {
	if strings.IndexRune(s, '{') < 0 {
		return false
	}
	if strings.IndexRune(s, '}') < 0 {
		return false
	}
	return true
}

func getReplPattern(s string) string {
	i := strings.IndexRune(s, '{')
	j := strings.IndexRune(s, '}')
	return string(s[i : j+1])
}

func getReplKey(s string) string {
	i := strings.IndexRune(s, '.')
	return string(s[i+1 : len(s)-1])
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

func repl(m map[string]interface{}, s string) (string, error) {
	for {
		if !hasReplPattern(s) {
			break
		}
		ptrn := getReplPattern(s)
		if !strings.HasPrefix(ptrn, "{claims.") {
			return "", fmt.Errorf("transform replace pattern %q is unsupported", ptrn)
		}
		v, err := getReplValue(m, getReplKey(ptrn))
		if err != nil {
			return "", err
		}
		s = strings.ReplaceAll(s, ptrn, v)
	}
	return s, nil
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
