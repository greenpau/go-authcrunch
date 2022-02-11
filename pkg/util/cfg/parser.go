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

package cfg

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	// ReplErrStr represents error replacement string.
	ReplErrStr string = "ERROR_REPLACEMENT"
)

// ArgRule represents a rules that applies to an arguments passed
// in a config.
type ArgRule struct {
	Min int `json:"min,omitempty" xml:"min,omitempty" yaml:"min,omitempty"`
	Max int `json:"max,omitempty" xml:"max,omitempty" yaml:"max,omitempty"`
}

// ValidateArg performs argument validation.
func ValidateArg(rules map[string]*ArgRule, k string, v []string) error {
	r, exists := rules[k]
	if !exists {
		return nil
	}
	if r.Min > len(v) {
		return errors.ErrValidateArgTooFew.WithArgs(k, len(v), r.Min)
	}
	if r.Max < len(v) {
		return errors.ErrValidateArgTooMany.WithArgs(k, len(v), r.Min)
	}
	return nil
}

// FindStrArr returns true if a string found in a slice.
func FindStrArr(arr []string, s string) bool {
	for _, x := range arr {
		if x == s {
			return true
		}
	}
	return false
}

// DedupStrArr returns deduplicated string array.
func DedupStrArr(arr []string) []string {
	var output []string
	m := make(map[string]interface{})
	for _, s := range arr {
		if _, exists := m[s]; exists {
			continue
		}
		m[s] = true
		output = append(output, s)
	}
	return output
}
