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
	"regexp"
	"strings"
)

type dataType int
type fieldMatchStrategy int

var (
	matchWithStrategyRgx *regexp.Regexp
	matchFieldRgx        *regexp.Regexp

	inputDataTypes = map[string]dataType{
		"roles":  dataTypeListStr,
		"email":  dataTypeStr,
		"origin": dataTypeStr,
		"name":   dataTypeStr,
		"realm":  dataTypeStr,
		"aud":    dataTypeListStr,
		"scopes": dataTypeListStr,
		"org":    dataTypeListStr,
		"jti":    dataTypeStr,
		"iss":    dataTypeStr,
		"sub":    dataTypeStr,
		"addr":   dataTypeStr,
		"method": dataTypeStr,
		"path":   dataTypeStr,
	}

	inputDataAliases = map[string]string{
		"id":           "jti",
		"audience":     "aud",
		"expires":      "exp",
		"issued":       "iat",
		"issuer":       "iss",
		"subject":      "sub",
		"mail":         "email",
		"role":         "roles",
		"group":        "roles",
		"groups":       "roles",
		"scope":        "scopes",
		"organization": "org",
		"address":      "addr",
		"ip":           "addr",
		"ipv4":         "addr",
		"http_method":  "method",
		"http_path":    "path",
	}
)

const (
	dataTypeUnknown dataType = 0
	dataTypeListStr dataType = 1
	dataTypeStr     dataType = 2
	dataTypeAny     dataType = 3

	fieldMatchUnknown  fieldMatchStrategy = 0
	fieldMatchReserved fieldMatchStrategy = 1
	fieldMatchExact    fieldMatchStrategy = 2
	fieldMatchPartial  fieldMatchStrategy = 3
	fieldMatchPrefix   fieldMatchStrategy = 4
	fieldMatchSuffix   fieldMatchStrategy = 5
	fieldMatchRegex    fieldMatchStrategy = 6
	fieldFound         fieldMatchStrategy = 7
	fieldNotFound      fieldMatchStrategy = 8
	fieldMatchAlways   fieldMatchStrategy = 9
)

type field struct {
	name   string
	length int
}

type expr struct {
	value  string
	length int
}

type config struct {
	field         string
	matchStrategy fieldMatchStrategy
	values        []string
	regexEnabled  bool
	alwaysTrue    bool
	exprDataType  dataType
	inputDataType dataType
	conditionType string
}

type aclRuleCondition interface {
	match(context.Context, interface{}) bool
	getConfig(context.Context) *config
}

// ruleAnyCondAlwaysMatchAnyInput returns positive match regardless of
// input fields, values, or conditions.
type ruleAnyCondAlwaysMatchAnyInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleCondFieldFound returns positive match regardless of input fields, values,
// or conditions, because the condition is only relevant to ACL rule itself.
type ruleCondFieldFound struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleCondFieldNotFound returns positive match regardless of input fields, values,
// or conditions, because the condition is only relevant to ACL rule itself.
type ruleCondFieldNotFound struct {
	field  *field
	exprs  []*expr
	config *config
}

func (c *ruleAnyCondAlwaysMatchAnyInput) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleAnyCondAlwaysMatchAnyInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleCondFieldFound) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleCondFieldFound) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleCondFieldNotFound) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleCondFieldNotFound) getConfig(ctx context.Context) *config {
	return c.config
}

// ruleListStrCondExactNegativeMatchListStrInput not matches a list of strings
// input against a list of strings where any of the input values not match at least
// one value of the condition using exact not match.
type ruleListStrCondExactNegativeMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialNegativeMatchListStrInput not matches a list of strings
// input against a list of strings where any of the input values not match at least
// one value of the condition using substring not match.
type ruleListStrCondPartialNegativeMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixNegativeMatchListStrInput not matches a list of strings
// input against a list of strings where any of the input values not match at least
// one value of the condition using string prefix not match.
type ruleListStrCondPrefixNegativeMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixNegativeMatchListStrInput not matches a list of strings
// input against a list of strings where any of the input values not match at least
// one value of the condition using string suffix not match.
type ruleListStrCondSuffixNegativeMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexNegativeMatchListStrInput not matches a list of strings
// input against a list of strings where any of the input values not match at least
// one value of the condition using regular expressions not match.
type ruleListStrCondRegexNegativeMatchListStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleStrCondExactNegativeMatchListStrInput not matches a list of strings input
// against a string condition using exact not match.
type ruleStrCondExactNegativeMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialNegativeMatchListStrInput not matches a list of strings input
// against a string condition using substring not match.
type ruleStrCondPartialNegativeMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixNegativeMatchListStrInput not matches a list of strings input
// against a string condition using string prefix not match.
type ruleStrCondPrefixNegativeMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixNegativeMatchListStrInput not matches a list of strings input
// against a string condition using string suffix not match.
type ruleStrCondSuffixNegativeMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexNegativeMatchListStrInput not matches a list of strings input
// against a string condition using regular expressions not match.
type ruleStrCondRegexNegativeMatchListStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

// ruleListStrCondExactNegativeMatchStrInput not matches an input string against a
// list of strings where any of the input values not match at least one value of
// the condition using exact not match.
type ruleListStrCondExactNegativeMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialNegativeMatchStrInput not matches an input string against
// a list of strings where any of the input values not match at least one value of
// the condition using substring not match.
type ruleListStrCondPartialNegativeMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixNegativeMatchStrInput not matches an input string against a
// list of strings where any of the input values not match at least one value of
// the condition using string prefix not match.
type ruleListStrCondPrefixNegativeMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixNegativeMatchStrInput not matches an input string against a
// list of strings where any of the input values not match at least one value of
// the condition using string suffix not match.
type ruleListStrCondSuffixNegativeMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexNegativeMatchStrInput not matches an input string against a
// list of strings where any of the input values not match at least one value of
// the condition using regular expressions not match.
type ruleListStrCondRegexNegativeMatchStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleStrCondExactNegativeMatchStrInput not matches an input string against a
// string condition using exact not match.
type ruleStrCondExactNegativeMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialNegativeMatchStrInput not matches an input string against a
// string condition using substring not match.
type ruleStrCondPartialNegativeMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixNegativeMatchStrInput not matches an input string against a
// string condition using string prefix not match.
type ruleStrCondPrefixNegativeMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixNegativeMatchStrInput not matches an input string against a
// string condition using string suffix not match.
type ruleStrCondSuffixNegativeMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexNegativeMatchStrInput not matches an input string against a
// string condition using regular expressions not match.
type ruleStrCondRegexNegativeMatchStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

// ruleListStrCondExactMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using exact match.
type ruleListStrCondExactMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialMatchListStrInput matches a list of strings input against
// a list of strings where any of the input values match at least one value of the
// condition using substring match.
type ruleListStrCondPartialMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using string prefix match.
type ruleListStrCondPrefixMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using string suffix match.
type ruleListStrCondSuffixMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using regular expressions match.
type ruleListStrCondRegexMatchListStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleStrCondExactMatchListStrInput matches a list of strings input against a
// string condition using exact match.
type ruleStrCondExactMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialMatchListStrInput matches a list of strings input against a
// string condition using substring match.
type ruleStrCondPartialMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixMatchListStrInput matches a list of strings input against a
// string condition using string prefix match.
type ruleStrCondPrefixMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixMatchListStrInput matches a list of strings input against a
// string condition using string suffix match.
type ruleStrCondSuffixMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexMatchListStrInput matches a list of strings input against a
// string condition using regular expressions match.
type ruleStrCondRegexMatchListStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

// ruleListStrCondExactMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using exact match.
type ruleListStrCondExactMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using substring match.
type ruleListStrCondPartialMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using string prefix match.
type ruleListStrCondPrefixMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using string suffix match.
type ruleListStrCondSuffixMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using regular expressions match.
type ruleListStrCondRegexMatchStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleStrCondExactMatchStrInput matches an input string against a string condition
// using exact match.
type ruleStrCondExactMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialMatchStrInput matches an input string against a string
// condition using substring match.
type ruleStrCondPartialMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixMatchStrInput matches an input string against a string
// condition using string prefix match.
type ruleStrCondPrefixMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixMatchStrInput matches an input string against a string
// condition using string suffix match.
type ruleStrCondSuffixMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexMatchStrInput matches an input string against a string condition
// using regular expressions match.
type ruleStrCondRegexMatchStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

func (c *ruleListStrCondExactNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if v == exp.value {
				return false
			}
		}
	}
	return true
}

func (c *ruleListStrCondPartialNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.Contains(v, exp.value) {
				return false
			}
		}
	}
	return true
}

func (c *ruleListStrCondPrefixNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasPrefix(v, exp.value) {
				return false
			}
		}
	}
	return true
}

func (c *ruleListStrCondSuffixNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasSuffix(v, exp.value) {
				return false
			}
		}
	}
	return true
}

func (c *ruleListStrCondRegexNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if exp.MatchString(v) {
				return false
			}
		}
	}
	return true
}

func (c *ruleStrCondExactNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if v == c.expr.value {
			return false
		}
	}
	return true
}

func (c *ruleStrCondPartialNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.Contains(v, c.expr.value) {
			return false
		}
	}
	return true
}

func (c *ruleStrCondPrefixNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasPrefix(v, c.expr.value) {
			return false
		}
	}
	return true
}

func (c *ruleStrCondSuffixNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasSuffix(v, c.expr.value) {
			return false
		}
	}
	return true
}

func (c *ruleStrCondRegexNegativeMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if c.expr.MatchString(v) {
			return false
		}
	}
	return true
}

func (c *ruleListStrCondExactNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if v.(string) == exp.value {
			return false
		}
	}
	return true
}

func (c *ruleListStrCondPartialNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.Contains(v.(string), exp.value) {
			return false
		}
	}
	return true
}

func (c *ruleListStrCondPrefixNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasPrefix(v.(string), exp.value) {
			return false
		}
	}
	return true
}

func (c *ruleListStrCondSuffixNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasSuffix(v.(string), exp.value) {
			return false
		}
	}
	return true
}

func (c *ruleListStrCondRegexNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if exp.MatchString(v.(string)) {
			return false
		}
	}
	return true
}

func (c *ruleStrCondExactNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if v.(string) == c.expr.value {
		return false
	}
	return true
}

func (c *ruleStrCondPartialNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.Contains(v.(string), c.expr.value) {
		return false
	}
	return true
}

func (c *ruleStrCondPrefixNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasPrefix(v.(string), c.expr.value) {
		return false
	}
	return true
}

func (c *ruleStrCondSuffixNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasSuffix(v.(string), c.expr.value) {
		return false
	}
	return true
}

func (c *ruleStrCondRegexNegativeMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if c.expr.MatchString(v.(string)) {
		return false
	}
	return true
}

func (c *ruleListStrCondExactMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if v == exp.value {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.Contains(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasPrefix(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasSuffix(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondRegexMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if exp.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func (c *ruleStrCondExactMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if v == c.expr.value {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.Contains(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasPrefix(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasSuffix(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondRegexMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if c.expr.MatchString(v) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondExactMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if v.(string) == exp.value {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.Contains(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasPrefix(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasSuffix(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondRegexMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if exp.MatchString(v.(string)) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondExactMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if v.(string) == c.expr.value {
		return true
	}
	return false
}

func (c *ruleStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.Contains(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasPrefix(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasSuffix(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondRegexMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if c.expr.MatchString(v.(string)) {
		return true
	}
	return false
}

func (c *ruleListStrCondExactNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexNegativeMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondExactNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexNegativeMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondExactMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondExactMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func init() {
	matchWithStrategyRgx = regexp.MustCompile(`^\s*((?P<negative_match>no)\s)?((?P<match_strategy>exact|partial|prefix|suffix|regex)\s)?match`)
	matchFieldRgx = regexp.MustCompile(`^\s*field\s+(?P<field_name>\S+)\s+(?P<field_exists>exists|not\s+exists)\s*$`)
}

func (cfg *config) AsMap() map[string]interface{} {
	m := make(map[string]interface{})
	m["field"] = cfg.field
	m["match_strategy"] = getMatchStrategyName(cfg.matchStrategy)
	if len(cfg.values) > 0 {
		m["values"] = cfg.values
	}
	m["regex_enabled"] = cfg.regexEnabled
	m["always_true"] = cfg.alwaysTrue
	m["expr_data_type"] = getDataTypeName(cfg.exprDataType)
	m["input_data_type"] = getDataTypeName(cfg.inputDataType)
	m["condition_type"] = cfg.conditionType
	return m
}

func extractMatchStrategy(s string) fieldMatchStrategy {
	switch s {
	case "", "exact":
		return fieldMatchExact
	case "partial":
		return fieldMatchPartial
	case "prefix":
		return fieldMatchPrefix
	case "suffix":
		return fieldMatchSuffix
	case "regex":
		return fieldMatchRegex
	case "exists":
		return fieldFound
	case "not exists":
		return fieldNotFound
	}
	return fieldMatchUnknown
}

func extractFieldNameValues(arr []string) (string, []string) {
	var k string
	var v []string
	var matchFound, fieldFound bool
	for _, a := range arr {
		if a == "match" {
			matchFound = true
			continue
		}
		if !matchFound {
			continue
		}
		if !fieldFound {
			k = a
			fieldFound = true
			continue
		}
		v = append(v, a)
	}
	if fieldFound {
		if alias, exists := inputDataAliases[k]; exists {
			k = alias
		}
	}
	return k, v
}

func validateFieldNameValues(line, k string, v []string) error {
	if k == "" {
		return errors.ErrACLRuleConditionSyntaxMatchFieldNotFound.WithArgs(line)
	}
	if len(v) == 0 {
		return errors.ErrACLRuleConditionSyntaxMatchValueNotFound.WithArgs(line)
	}
	for _, s := range v {
		switch s {
		case "exact", "partial", "prefix", "suffix", "regex":
			return errors.ErrACLRuleConditionSyntaxReservedWordUsage.WithArgs(s, line)
		}
	}
	return nil
}

func extractCondDataType(line string, inputDataType dataType, values []string) (dataType, error) {
	switch inputDataType {
	case dataTypeListStr, dataTypeStr:
		if len(values) == 1 {
			return dataTypeStr, nil
		}
		return dataTypeListStr, nil
	case dataTypeAny:
		return dataTypeAny, nil
	}
	return dataTypeUnknown, errors.ErrACLRuleConditionSyntaxCondDataType.WithArgs(line)
}

func extractInputDataType(fieldName string) dataType {
	if tp, exists := inputDataTypes[fieldName]; exists {
		return tp
	}
	return dataTypeAny
}

func newACLRuleCondition(ctx context.Context, tokens []string) (aclRuleCondition, error) {
	var inputDataType, condDataType dataType
	var matchStrategy fieldMatchStrategy
	var negativeMatch bool
	var fieldName string
	var values []string

	line := strings.Join(tokens, " ")

	switch {
	case line == "match any":
		matchStrategy = fieldMatchAlways
		fieldName = "exp"
		inputDataType = dataTypeAny
		condDataType = dataTypeAny
	case matchFieldRgx.Match([]byte(line)):
		matched := matchFieldRgx.FindStringSubmatch(line)
		for i, k := range matchFieldRgx.SubexpNames() {
			if i > 0 && i <= len(matched) {
				switch k {
				case "field_exists":
					matchStrategy = extractMatchStrategy(matched[i])
				case "field_name":
					fieldName = matched[i]
					if alias, exists := inputDataAliases[fieldName]; exists {
						fieldName = alias
					}
				}
			}
		}
		inputDataType = dataTypeAny
		condDataType = dataTypeAny
	case matchWithStrategyRgx.Match([]byte(line)):
		matched := matchWithStrategyRgx.FindStringSubmatch(line)
		for i, k := range matchWithStrategyRgx.SubexpNames() {
			if i > 0 && i <= len(matched) {
				switch k {
				case "match_strategy":
					matchStrategy = extractMatchStrategy(matched[i])
					if matchStrategy == fieldMatchUnknown {
						matchStrategy = fieldMatchExact
					}
				case "negative_match":
					if matched[i] == "no" {
						negativeMatch = true
					}
				}
			}
		}
		fieldName, values = extractFieldNameValues(tokens)
	default:
		return nil, errors.ErrACLRuleConditionSyntaxMatchNotFound.WithArgs(line)
	}

	if matchStrategy == fieldMatchUnknown {
		return nil, errors.ErrACLRuleConditionSyntaxStrategyNotFound.WithArgs(line)
	}

	switch matchStrategy {
	case fieldMatchAlways, fieldFound, fieldNotFound:
	default:
		if err := validateFieldNameValues(line, fieldName, values); err != nil {
			return nil, err
		}
		inputDataType = extractInputDataType(fieldName)
		var err error
		condDataType, err = extractCondDataType(line, inputDataType, values)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case matchStrategy == fieldFound:
		// Match: Field Found, Condition Type: Any, Input Type: Any
		c := &ruleCondFieldFound{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldFound,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  inputDataType,
				inputDataType: condDataType,
				conditionType: `ruleCondFieldFound`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
			exprs: []*expr{},
		}
		return c, nil
	case matchStrategy == fieldNotFound:
		// Match: Field Found, Condition Type: Any, Input Type: Any
		c := &ruleCondFieldNotFound{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldNotFound,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  inputDataType,
				inputDataType: condDataType,
				conditionType: `ruleCondFieldNotFound`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
			exprs: []*expr{},
		}
		return c, nil
	case matchStrategy == fieldMatchAlways:
		// Match: Always, Condition Type: Any, Input Type: Any
		c := &ruleAnyCondAlwaysMatchAnyInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchAlways,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    true,
				exprDataType:  inputDataType,
				inputDataType: condDataType,
				conditionType: `ruleAnyCondAlwaysMatchAnyInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
			exprs: []*expr{},
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// No match: Exact, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondExactNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// No match: Partial, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPartialNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// No match: Prefix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPrefixNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// No match: Suffix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondSuffixNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// No match: Regex, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondRegexNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// No match: Exact, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondExactNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// No match: Partial, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPartialNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// No match: Prefix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPrefixNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// No match: Suffix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondSuffixNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// No match: Regex, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondRegexNegativeMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexNegativeMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// No match: Exact, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondExactNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// No match: Partial, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPartialNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// No match: Prefix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPrefixNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// No match: Suffix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondSuffixNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// No match: Regex, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondRegexNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// No match: Exact, Condition Type: Str, Input Type: Str
		c := &ruleStrCondExactNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// No match: Partial, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPartialNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// No match: Prefix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPrefixNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// No match: Suffix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondSuffixNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case negativeMatch && matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// No match: Regex, Condition Type: Str, Input Type: Str
		c := &ruleStrCondRegexNegativeMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexNegativeMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Exact, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondExactMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Partial, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPartialMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Prefix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPrefixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Suffix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondSuffixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Regex, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondRegexMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Exact, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondExactMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Partial, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPartialMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Prefix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPrefixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Suffix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondSuffixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Regex, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondRegexMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Exact, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondExactMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Partial, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPartialMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Prefix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPrefixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Suffix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondSuffixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Regex, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondRegexMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Exact, Condition Type: Str, Input Type: Str
		c := &ruleStrCondExactMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Partial, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPartialMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Prefix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPrefixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Suffix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondSuffixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Regex, Condition Type: Str, Input Type: Str
		c := &ruleStrCondRegexMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil

	}
	return nil, errors.ErrACLRuleConditionSyntaxUnsupported.WithArgs(line)
}

func getMatchStrategyName(s fieldMatchStrategy) string {
	switch s {
	case fieldMatchExact:
		return "fieldMatchExact"
	case fieldMatchPartial:
		return "fieldMatchPartial"
	case fieldMatchPrefix:
		return "fieldMatchPrefix"
	case fieldMatchSuffix:
		return "fieldMatchSuffix"
	case fieldMatchRegex:
		return "fieldMatchRegex"
	case fieldFound:
		return "fieldFound"
	case fieldNotFound:
		return "fieldNotFound"
	case fieldMatchAlways:
		return "fieldMatchAlways"
	case fieldMatchReserved:
		return "fieldMatchReserved"
	}
	return "fieldMatchUnknown"
}
func getDataTypeName(s dataType) string {
	switch s {
	case dataTypeListStr:
		return "dataTypeListStr"
	case dataTypeStr:
		return "dataTypeStr"
	case dataTypeAny:
		return "dataTypeAny"
	}
	return "dataTypeUnknown"
}
