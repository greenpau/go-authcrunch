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

package errors

// ACL Errors
const (
	ErrAccessListRuleConfig                     StandardError = "acl rule configuration error: %v: %v"
	ErrAccessListRuleConditionConfig            StandardError = "acl rule condition configuration error: %v: %v"
	ErrAccessListNoRules                        StandardError = "acl has no rules"
	ErrACLRuleConditionSyntaxMatchNotFound      StandardError = "invalid condition syntax, matcher not found: %v"
	ErrACLRuleConditionSyntaxMatchFieldNotFound StandardError = "invalid condition syntax, matcher field not found: %v"
	ErrACLRuleConditionSyntaxMatchValueNotFound StandardError = "invalid condition syntax, matcher values not found: %v"
	ErrACLRuleConditionSyntaxCondDataType       StandardError = "invalid condition syntax, matcher condition data type unsupported: %v"
	ErrACLRuleConditionSyntaxUnsupported        StandardError = "invalid condition syntax, failed creating rule condition: %v"
	ErrACLRuleConditionSyntaxStrategyNotFound   StandardError = "invalid condition syntax, matcher strategy not found: %v"
	ErrACLRuleConditionSyntaxReservedWordUsage  StandardError = "invalid condition syntax, found reserved keyword %q: %v"

	ErrACLRuleSyntaxExtractCondToken   StandardError = "invalid rule syntax, failed to extract condition tokens: %v"
	ErrACLRuleSyntaxDuplicateField     StandardError = "invalid rule syntax, duplicate field: %s"
	ErrACLRuleSyntaxExtractActionToken StandardError = "invalid rule syntax, failed to extract action tokens: %v"

	ErrACLRuleSyntaxAllowPreceed       StandardError = "invalid rule syntax, %q must preceed stop/counter/log directives"
	ErrACLRuleSyntaxTagFollowedByValue StandardError = "invalid rule syntax, %q tag must be followed by value"
	ErrACLRuleSyntaxInvalidToken       StandardError = "invalid rule syntax, invalid %q token"
	ErrACLRuleSyntaxCondNotFound       StandardError = "invalid rule syntax, no match conditions found"
	ErrACLRuleSyntaxTypeUnsupported    StandardError = "invalid rule syntax, type %q is unsupported"
	ErrACLRuleSyntaxLoggerNotFound     StandardError = "invalid rule syntax, no logger found for log enabled rule: %s"

	ErrACLRuleSyntax StandardError = "invalid rule syntax: %v"
)
