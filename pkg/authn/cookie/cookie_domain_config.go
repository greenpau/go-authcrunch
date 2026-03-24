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

package cookie

// DomainConfig represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type DomainConfig struct {
	Seq                int    `json:"seq,omitempty" xml:"seq,omitempty" yaml:"seq,omitempty"`
	Domain             string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
	Path               string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Lifetime           int    `json:"lifetime,omitempty" xml:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Insecure           bool   `json:"insecure,omitempty" xml:"insecure,omitempty" yaml:"insecure,omitempty"`
	SameSite           string `json:"same_site,omitempty" xml:"same_site,omitempty" yaml:"same_site,omitempty"`
	StripDomainEnabled bool   `json:"strip_domain_enabled,omitempty" xml:"strip_domain_enabled,omitempty" yaml:"strip_domain_enabled,omitempty"`
}
