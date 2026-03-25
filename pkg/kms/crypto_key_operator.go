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

// CryptoKeyOperator represents CryptoKey operator.
type CryptoKeyOperator struct {
	Token   *CryptoKeyTokenOperator `json:"token,omitempty" xml:"token,omitempty" yaml:"token,omitempty"`
	Secret  interface{}             `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Capable bool                    `json:"capable,omitempty" xml:"capable,omitempty" yaml:"capable,omitempty"`
}

// NewCryptoKeyOperator returns an instance of CryptoKeyOperator.
func NewCryptoKeyOperator() *CryptoKeyOperator {
	op := &CryptoKeyOperator{}
	op.Token = NewCryptoKeyTokenOperator()
	return op
}
