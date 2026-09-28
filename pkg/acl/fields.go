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

package acl

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	// FieldTypeString matches a scalar string claim.
	FieldTypeString = "string"
	// FieldTypeStringList matches a claim containing only strings.
	FieldTypeStringList = "string_list"
)

var customFieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,127}$`)

// FieldConfig binds a policy-local ACL name to an exact top-level claim key.
// Claim is literal: punctuation does not select nested objects or a remote URL.
type FieldConfig struct {
	Name  string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Claim string `json:"claim,omitempty" xml:"claim,omitempty" yaml:"claim,omitempty"`
	Type  string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// Validate checks a field declaration without modifying it or echoing its input.
func (c *FieldConfig) Validate() error {
	if c == nil {
		return errors.ErrACLFieldConfig.WithArgs("field must not be null")
	}
	if !customFieldName.MatchString(c.Name) {
		return errors.ErrACLFieldConfig.WithArgs("name must be an ASCII identifier of 1-128 characters")
	}
	if _, ok := inputDataTypes[c.Name]; ok {
		return errors.ErrACLFieldConfig.WithArgs("name is reserved")
	}
	if _, ok := inputDataAliases[c.Name]; ok {
		return errors.ErrACLFieldConfig.WithArgs("name is reserved")
	}
	switch c.Name {
	case "exp", "iat", "nbf", "acl", "any", "match", "field", "exists", "not", "no",
		"exact", "partial", "prefix", "suffix", "regex", "allow", "deny", "stop", "with", "to":
		return errors.ErrACLFieldConfig.WithArgs("name is reserved")
	}
	if c.Claim == "" || strings.TrimSpace(c.Claim) != c.Claim || !utf8.ValidString(c.Claim) || strings.ContainsFunc(c.Claim, unicode.IsControl) {
		return errors.ErrACLFieldConfig.WithArgs("claim must be a nonempty literal key without control characters or surrounding whitespace")
	}
	if c.Type != FieldTypeString && c.Type != FieldTypeStringList {
		return errors.ErrACLFieldConfig.WithArgs("type must be string or string_list")
	}
	return nil
}

// NewAccessListWithFields snapshots custom field definitions for this list.
// Nil or empty definitions retain the behavior of NewAccessList. Add rules and
// set options before publishing the list; evaluation never mutates definitions.
func NewAccessListWithFields(fields []*FieldConfig) (*AccessList, error) {
	list := NewAccessList()
	list.fieldTypes = make(map[string]dataType, len(fields))
	list.customFields = make(map[string]FieldConfig, len(fields))
	list.usedFields = make(map[string]FieldConfig)
	for _, field := range fields {
		if err := field.Validate(); err != nil {
			return nil, err
		}
		if _, ok := list.customFields[field.Name]; ok {
			return nil, errors.ErrACLFieldConfig.WithArgs("duplicate name")
		}
		list.customFields[field.Name] = *field
		kind := dataTypeStr
		if field.Type == FieldTypeStringList {
			kind = dataTypeListStr
		}
		list.fieldTypes[field.Name] = kind
	}
	return list, nil
}

// AllowWithClaims evaluates normalized identity/request data plus authenticated
// claims. Only custom fields referenced by rules are copied from claims, using
// each declaration's exact Claim key. Claim data never overrides standard ACL
// fields. Both maps remain unchanged. This method does not authenticate claims.
//
// Missing fields stay absent; null or incorrectly typed referenced values deny
// the whole evaluation, even before an earlier allow-stop or a default allow.
func (acl *AccessList) AllowWithClaims(ctx context.Context, data, claims map[string]any) bool {
	data, valid := acl.prepareData(data, claims, true)
	return valid && acl.allow(ctx, data)
}

func (acl *AccessList) prepareData(data, source map[string]any, useClaimNames bool) (map[string]any, bool) {
	if len(acl.customFields) == 0 {
		return data, true
	}
	out := maps.Clone(data)
	if out == nil {
		out = make(map[string]any, len(acl.usedFields))
	}
	// A preexisting alias cannot substitute for an absent configured source.
	for name := range acl.customFields {
		delete(out, name)
	}
	for name, field := range acl.usedFields {
		key := name
		if useClaimNames {
			key = field.Claim
		}
		value, found := source[key]
		if !found {
			continue
		}
		normalized, valid := normalizeCustomField(value, field.Type)
		if !valid {
			return nil, false
		}
		out[name] = normalized
	}
	return out, true
}

func normalizeCustomField(value any, kind string) (any, bool) {
	if kind == FieldTypeString {
		text, ok := value.(string)
		return text, ok
	}
	switch values := value.(type) {
	case []string:
		// Typed nil slices serialize as null and must agree with JSON input.
		if values == nil {
			return nil, false
		}
		return slices.Clone(values), true
	case []any:
		if values == nil {
			return nil, false
		}
		out := make([]string, len(values))
		for i, entry := range values {
			text, ok := entry.(string)
			if !ok {
				return nil, false
			}
			out[i] = text
		}
		return out, true
	default:
		return nil, false
	}
}

// Empty custom lists exist, but do not grant a value match through negation.
// Standard list matchers retain their established empty-list behavior.
type nonemptyListCondition struct{ aclRuleCondition }

func (c *nonemptyListCondition) match(ctx context.Context, value any) bool {
	values, ok := value.([]string)
	return ok && len(values) != 0 && c.aclRuleCondition.match(ctx, values)
}
