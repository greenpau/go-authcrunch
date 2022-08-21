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

package sso

import (
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// RequestKind represents the type of SSO provider request.
type RequestKind int

const (
	ssoPrefix       = "/apps/sso/"
	metadataKeyword = "/metadata.xml"
	ssumeKeyword    = "/assume"

	// UnknownRequest represents unspecified request type.
	UnknownRequest RequestKind = iota
	// MetadataRequest represents metadata request type.
	MetadataRequest
	// AssumeRoleRequest represents role assumption request type.
	AssumeRoleRequest
	// MenuRequest represents role selection request type.
	MenuRequest
)

// Request represents sso provider request.
type Request struct {
	ProviderName string      `json:"provider_name,omitempty" xml:"provider_name,omitempty" yaml:"provider_name,omitempty"`
	Kind         RequestKind `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Params       string      `json:"params,omitempty" xml:"params,omitempty" yaml:"params,omitempty"`
}

// ParseRequestURL extracts provider name and request type from URL.
func ParseRequestURL(r *http.Request) (*Request, error) {
	req := &Request{}

	s := r.URL.Path
	i := strings.Index(s, ssoPrefix)
	if i < 0 {
		return nil, errors.ErrSingleSignOnProviderRequestMalformed
	}
	s = strings.TrimPrefix(s[i:], ssoPrefix)

	parts := strings.SplitN(s, "/", 2)
	req.ProviderName = parts[0]

	if len(parts) == 1 {
		if parts[0] == "" {
			return nil, errors.ErrSingleSignOnProviderRequestMalformed
		}
		req.Kind = MenuRequest
		return req, nil
	}

	if strings.HasPrefix(parts[1], "assume/") {
		params := strings.TrimPrefix(parts[1], "assume/")
		if params == "" {
			return nil, errors.ErrSingleSignOnProviderRequestMalformed
		}
		req.Params = params
		req.Kind = AssumeRoleRequest
		return req, nil
	}

	if parts[1] == "metadata.xml" {
		req.Kind = MetadataRequest
		return req, nil
	}

	return nil, errors.ErrSingleSignOnProviderRequestMalformed
}
