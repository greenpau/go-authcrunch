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

package identity

// CreditCardAssociations is a collection of most popular credit card issuers.
var CreditCardAssociations = []*CreditCardAssociation{
	&CreditCardAssociation{
		Name:       "American Express",
		CodeName:   "CID",
		CodeFormat: "NNNN",
		Aliases: []string{
			"amex", "AMEX",
		},
	},
	&CreditCardAssociation{
		Name: "Diners Club",
		Aliases: []string{
			"diners",
		},
		CodeName:   "Security Code",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Discover",
		Aliases: []string{
			"discover",
		},
		CodeName:   "CID",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Mastercard",
		Aliases: []string{
			"mastercard",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
	&CreditCardAssociation{
		Name: "Visa",
		Aliases: []string{
			"visa",
		},
		CodeName:   "CVC2",
		CodeFormat: "NNN",
	},
}

// CreditCardAssociation represents a credit card association, e.g. Visa,
// American Express, etc., to a credit card
type CreditCardAssociation struct {
	Name       string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Aliases    []string `json:"aliases,omitempty" xml:"aliases,omitempty" yaml:"aliases,omitempty"`
	CodeName   string   `json:"code_name,omitempty" xml:"code_name,omitempty" yaml:"code_name,omitempty"`
	CodeFormat string   `json:"code_format,omitempty" xml:"code_format,omitempty" yaml:"code_format,omitempty"`
}

// NewCreditCardAssociation returns an instance of
func NewCreditCardAssociation() *CreditCardAssociation {
	return &CreditCardAssociation{}
}
