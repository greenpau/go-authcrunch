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

package saml

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	samllib "github.com/crewjam/saml"
	"github.com/greenpau/go-authcrunch/pkg/requests"

	"go.uber.org/zap"
)

// Authenticate performs authentication. The embedding application must supply
// Upstream.SessionID as dedicated SAML browser-binding proof on both the
// initiating request and callback. The portal consumer derives it from its
// protected, distinct SAML cookie. RelayState is a separate, unpredictable
// transaction identifier and never acts as a callback destination.
func (b *IdentityProvider) Authenticate(r *requests.Request) error {
	r.Response.Code = http.StatusBadRequest
	callbackURL := r.Upstream.BaseURL + path.Join(r.Upstream.BasePath, r.Upstream.Method, r.Upstream.Realm)
	sp, serviceProviderExists := b.serviceProviders[callbackURL]
	if !serviceProviderExists {
		return fmt.Errorf("unsupported ACS URL %s", callbackURL)
	}
	if r.Upstream.Request.Method == http.MethodGet {
		if r.Upstream.SessionID == "" {
			return fmt.Errorf("SAML browser binding is missing")
		}
		authnRequest, err := sp.MakeAuthenticationRequest(b.loginURL, samllib.HTTPRedirectBinding, samllib.HTTPPostBinding)
		if err != nil {
			return fmt.Errorf("failed creating SAML authentication request: %w", err)
		}
		relayState, err := b.state.add(r.Upstream.SessionID, callbackURL, authnRequest.ID)
		if err != nil {
			return err
		}
		redirectURL, err := authnRequest.Redirect(relayState, sp)
		if err != nil {
			b.state.del(relayState)
			return fmt.Errorf("failed creating SAML authentication redirect: %w", err)
		}
		r.Response.Code = http.StatusFound
		r.Response.RedirectURL = redirectURL.String()
		return nil
	}
	if r.Upstream.Request.Method != http.MethodPost {
		return fmt.Errorf("request method is not GET or POST")
	}

	if 500 > r.Upstream.Request.ContentLength || r.Upstream.Request.ContentLength > 30000 {
		return fmt.Errorf("request payload is not 500 to 300000 bytes: %d", r.Upstream.Request.ContentLength)
	}
	contentType := r.Upstream.Request.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return fmt.Errorf("request content type is not application/x-www-form-urlencoded")
	}
	if err := r.Upstream.Request.ParseForm(); err != nil {
		return fmt.Errorf("failed to parse form: %v", err)
	}
	responseValues := r.Upstream.Request.PostForm["SAMLResponse"]
	if len(responseValues) != 1 || responseValues[0] == "" {
		return fmt.Errorf("request form must have exactly one SAMLResponse field")
	}
	relayStateValues := r.Upstream.Request.PostForm["RelayState"]
	if len(relayStateValues) != 1 || relayStateValues[0] == "" {
		return fmt.Errorf("request form must have exactly one RelayState field")
	}
	requestID, ok := b.state.consume(relayStateValues[0], r.Upstream.SessionID, callbackURL)
	if !ok {
		return fmt.Errorf("SAML RelayState browser binding is invalid or expired")
	}
	samlResponseBytes, err := base64.StdEncoding.DecodeString(responseValues[0])
	if err != nil {
		return fmt.Errorf("failed to decode SAMLResponse: %v", err)
	}

	if b.config.Driver == "azure" {
		if !strings.Contains(r.Upstream.Request.Header.Get("Origin"), "login.microsoftonline.com") && !strings.Contains(r.Upstream.Request.Header.Get("Referer"), "windowsazure.com") {
			return fmt.Errorf("origin does not contain login.microsoftonline.com and Referer is not windowsazure.com")
		}
	}

	samlAssertions, err := sp.ParseXMLResponse(samlResponseBytes, []string{requestID}, sp.AcsURL)
	if err != nil {
		return fmt.Errorf("failed to ParseXMLResponse: %s", err)
	}

	m := make(map[string]interface{})
	metadata := make(map[string]interface{})
	for _, attrStatement := range samlAssertions.AttributeStatements {

		for _, attrEntry := range attrStatement.Attributes {
			if len(attrEntry.Values) == 0 {
				continue
			}
			switch {
			case strings.HasSuffix(attrEntry.Name, "Attributes/MaxSessionDuration"):
				multiplier, err := strconv.Atoi(attrEntry.Values[0].Value)
				if err != nil {
					b.logger.Error(
						"Failed parsing Attributes/MaxSessionDuration",
						zap.String("request_id", r.ID),
						zap.String("error", err.Error()),
					)
					continue
				}
				m["exp"] = time.Now().Add(time.Duration(multiplier) * time.Second).Unix()
			case strings.HasSuffix(attrEntry.Name, "identity/claims/displayname"):
				if attrEntry.Values[0].Value != "" {
					m["name"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "identity/claims/emailaddress"):
				if attrEntry.Values[0].Value != "" {
					m["email"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "identity/claims/identityprovider"):
				if attrEntry.Values[0].Value != "" {
					m["origin"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "schemas.microsoft.com/identity/claims/objectidentifier"):
				if attrEntry.Values[0].Value != "" {
					metadata["oid"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"):
				if attrEntry.Values[0].Value != "" {
					metadata["upn"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "identity/claims/name"):
				if attrEntry.Values[0].Value != "" {
					m["sub"] = attrEntry.Values[0].Value
				}
			case strings.HasSuffix(attrEntry.Name, "Attributes/Role"):
				roles := []string{}
				for _, attrEntryElement := range attrEntry.Values {
					roles = append(roles, attrEntryElement.Value)
				}
				if len(roles) > 0 {
					m["roles"] = roles
				}
			}
		}
	}

	for _, k := range []string{"email", "name"} {
		if _, exists := m[k]; !exists {
			return fmt.Errorf("SAML authorization failed, mandatory %s attribute not found: %v", k, m)
		}
	}

	if len(metadata) > 0 {
		m["metadata"] = metadata
	}

	r.Response.Code = 200
	r.Response.Payload = m
	return nil
}
