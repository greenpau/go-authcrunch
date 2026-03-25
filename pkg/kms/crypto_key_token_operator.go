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

package kms

// CryptoKeyTokenOperator represents CryptoKeyOperator token operator.
type CryptoKeyTokenOperator struct {
	ID               string                 `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name             string                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	MaxLifetime      int                    `json:"max_lifetime,omitempty" xml:"max_lifetime,omitempty" yaml:"max_lifetime,omitempty"`
	Methods          map[string]interface{} `json:"methods,omitempty" xml:"methods,omitempty" yaml:"methods,omitempty"`
	CookieNames      map[string]interface{} `json:"cookie_names,omitempty" xml:"cookie_names,omitempty" yaml:"cookie_names,omitempty"`
	QueryParamNames  map[string]interface{} `json:"query_param_names,omitempty" xml:"query_param_names,omitempty" yaml:"query_param_names,omitempty"`
	HeaderNames      map[string]interface{} `json:"header_names,omitempty" xml:"header_names,omitempty" yaml:"header_names,omitempty"`
	PreferredMethods []string               `json:"preferred_methods,omitempty" xml:"preferred_methods,omitempty" yaml:"preferred_methods,omitempty"`
	DefaultMethod    string                 `json:"default_method,omitempty" xml:"default_method,omitempty" yaml:"default_method,omitempty"`
	Capable          bool                   `json:"capable,omitempty" xml:"capable,omitempty" yaml:"capable,omitempty"`
	injectKeyID      bool
}

// NewCryptoKeyTokenOperator returns an instance of CryptoKeyTokenOperator.
func NewCryptoKeyTokenOperator() *CryptoKeyTokenOperator {
	op := &CryptoKeyTokenOperator{}
	op.Methods = make(map[string]interface{})
	op.CookieNames = make(map[string]interface{})
	op.QueryParamNames = make(map[string]interface{})
	op.HeaderNames = make(map[string]interface{})
	return op
}
