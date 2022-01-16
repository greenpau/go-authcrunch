// Copyright 2020 Paul Greenberg greenpau@outlook.com
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

package registration

// Config represents a common set of configuration settings for user registration
type Config struct {
	// The switch determining whether the registration is enabled/disabled.
	Disabled bool `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	// The title of the registration page
	Title string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	// The mandatory registration code. It is possible adding multiple
	// codes, comma separated.
	Code string `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	// The file path to registration database.
	Dropbox string `json:"dropbox,omitempty" xml:"dropbox,omitempty" yaml:"dropbox,omitempty"`
	// The switch determining whether a user must accept terms and conditions
	RequireAcceptTerms bool `json:"require_accept_terms,omitempty" xml:"require_accept_terms,omitempty" yaml:"require_accept_terms,omitempty"`
	// The switch determining whether the domain associated with an email has
	// a valid MX DNS record.
	RequireDomainMailRecord bool `json:"require_domain_mx,omitempty" xml:"require_domain_mx,omitempty" yaml:"require_domain_mx,omitempty"`
	// The link to terms and conditions document.
	TermsConditionsLink string `json:"terms_conditions_link,omitempty" xml:"terms_conditions_link,omitempty" yaml:"terms_conditions_link,omitempty"`
	// The link to privacy policy document.
	PrivacyPolicyLink string `json:"privacy_policy_link,omitempty" xml:"privacy_policy_link,omitempty" yaml:"privacy_policy_link,omitempty"`
}
