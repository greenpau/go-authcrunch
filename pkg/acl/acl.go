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

package acl

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"go.uber.org/zap"
)

// AccessList is a collection of access list rules.
type AccessList struct {
	config       []*RuleConfiguration
	rules        []aclRule
	logger       *zap.Logger
	defaultAllow bool
	fieldTypes   map[string]dataType
	customFields map[string]FieldConfig
	usedFields   map[string]FieldConfig
}

// NewAccessList returns an instance of AccessList.
func NewAccessList() *AccessList {
	return &AccessList{
		rules: []aclRule{},
	}
}

// GetRules returns configured ACL rules.
func (acl *AccessList) GetRules() []*RuleConfiguration {
	return acl.config
}

// SetDefaultAllowAction sets default allow for the AccessList,
// i.e. the AccessList fails open.
func (acl *AccessList) SetDefaultAllowAction() {
	acl.defaultAllow = true
}

// SetLogger adds a logger to AccessList.
func (acl *AccessList) SetLogger(logger *zap.Logger) {
	acl.logger = logger
}

// AddRules adds multiple rules to AccessList.
func (acl *AccessList) AddRules(ctx context.Context, cfgs []*RuleConfiguration) error {
	for _, cfg := range cfgs {
		if err := acl.AddRule(ctx, cfg); err != nil {
			return err
		}
	}
	return nil
}

// AddRule adds a rule to AccessList.
func (acl *AccessList) AddRule(ctx context.Context, cfg *RuleConfiguration) error {
	if cfg == nil {
		return errors.ErrAccessListRuleConfig.WithArgs(len(acl.rules), "rule must not be null")
	}
	rule, err := newACLRuleWithFields(ctx, len(acl.rules), cfg, acl.logger, acl.fieldTypes)
	if err != nil {
		return err
	}
	acl.config = append(acl.config, cfg)
	acl.rules = append(acl.rules, rule)
	for _, name := range rule.getConfig(ctx).fields {
		if field, ok := acl.customFields[name]; ok {
			acl.usedFields[name] = field
		}
	}
	return nil
}

// AsMap returns acl configuration as map.
func (acl *AccessList) AsMap() map[string]interface{} {
	m := make(map[string]interface{})
	rules := []map[string]interface{}{}
	for _, rule := range acl.rules {
		ruleConfig := rule.getConfig(context.Background())
		rules = append(rules, ruleConfig.AsMap())
	}
	if len(rules) > 0 {
		m["rules"] = rules
	}
	m["count"] = len(rules)
	return m
}

// Allow evaluates normalized identity and request data. Declared custom fields
// are read by their ACL names and strictly type-checked before evaluating rules.
// Configure the list completely before sharing it between requests.
func (acl *AccessList) Allow(ctx context.Context, data map[string]any) bool {
	data, valid := acl.prepareData(data, data, false)
	return valid && acl.allow(ctx, data)
}

func (acl *AccessList) allow(ctx context.Context, data map[string]any) bool {
	var grantAccess bool
	for _, rule := range acl.rules {
		v := rule.eval(ctx, data)
		switch v {
		case ruleVerdictAllowStop:
			return true
		case ruleVerdictAllow:
			grantAccess = true
		case ruleVerdictDenyStop:
			return false
		case ruleVerdictDeny:
			return false
		}
	}
	if grantAccess || acl.defaultAllow {
		return true
	}
	return false
}

// GetFieldDataType return data type for a particular data field.
func GetFieldDataType(s string) (string, string) {
	k := s
	dt := dataTypeUnknown
	if v, exists := inputDataAliases[s]; exists {
		if vdt, exists := inputDataTypes[v]; exists {
			dt = vdt
			k = v
		}
	} else {
		if sdt, exists := inputDataTypes[s]; exists {
			dt = sdt
		}
	}
	switch dt {
	case dataTypeListStr:
		return k, "list_str"
	case dataTypeStr:
		return k, "str"
	}
	return k, ""
}
