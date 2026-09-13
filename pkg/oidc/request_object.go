// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// requestObjectParameters implements Core 6.1/6.3.3 parameter assembly for
// unsecured Request Objects. This is an alternative encoding of untrusted
// authorization parameters, NEVER authentication or client identity evidence.
// Signed/encrypted objects and remote request_uri fetching are not supported.
func (o *Provider) requestObjectParameters(outer url.Values) (url.Values, string) {
	raw := outer.Get("request")
	if raw == "" {
		return outer, ""
	}
	if outer.Get("request_uri") != "" || outer.Get("client_id") == "" || outer.Get("response_type") == "" || !slices.Contains(strings.Fields(outer.Get("scope")), "openid") {
		return nil, "invalid_request"
	}
	parts := strings.Split(raw, ".")
	if len(raw) > oidcMaxRequestBytes || len(parts) != 3 || parts[2] != "" {
		return nil, "invalid_request_object"
	}
	header, err := oidcRequestObjectPart(parts[0])
	var algorithm string
	if err != nil || json.Unmarshal(header["alg"], &algorithm) != nil || algorithm != "none" {
		return nil, "invalid_request_object"
	}
	for _, unsupported := range []string{"crit", "b64", "enc", "zip"} {
		if _, exists := header[unsupported]; exists {
			return nil, "invalid_request_object"
		}
	}
	object, err := oidcRequestObjectPart(parts[1])
	if err != nil {
		return nil, "invalid_request_object"
	}
	for _, nested := range []string{"request", "request_uri"} {
		if _, exists := object[nested]; exists {
			return nil, "invalid_request_object"
		}
	}
	for _, binding := range []string{"client_id", "response_type", "iss"} {
		if value, exists := object[binding]; exists {
			var actual string
			expected := outer.Get(binding)
			if binding == "iss" {
				expected = outer.Get("client_id")
			}
			if json.Unmarshal(value, &actual) != nil || actual != expected {
				return nil, "invalid_request_object"
			}
		}
	}
	if value, exists := object["aud"]; exists {
		var audience string
		var audiences []string
		if json.Unmarshal(value, &audience) == nil {
			audiences = []string{audience}
		} else if json.Unmarshal(value, &audiences) != nil {
			return nil, "invalid_request_object"
		}
		if !slices.Contains(audiences, o.config.Issuer) {
			return nil, "invalid_request_object"
		}
	}
	for _, name := range []string{"exp", "nbf", "iat"} {
		if value, exists := object[name]; exists {
			number, err := strconv.ParseFloat(string(value), 64)
			now := o.now()
			seconds := float64(now.Unix()) + float64(now.Nanosecond())/1e9
			if err != nil || number < 0 || (name == "exp" && number <= seconds) || (name != "exp" && number > seconds) {
				return nil, "invalid_request_object"
			}
		}
	}
	merged := make(url.Values, len(outer)+len(object))
	for name, values := range outer {
		merged[name] = slices.Clone(values)
	}
	merged.Del("request")
	for name, raw := range object {
		switch name {
		case "iss", "aud", "exp", "nbf", "iat", "jti":
			continue
		case "max_age":
			if _, err := strconv.ParseUint(string(raw), 10, 63); err != nil {
				return nil, "invalid_request_object"
			}
			merged.Set(name, string(raw))
		case "claims":
			// The claims parameter is not supported; preserve its JSON encoding
			// for the normal authorization validator to ignore.
			merged.Set(name, string(raw))
		case "client_id", "response_type", "redirect_uri", "scope", "state", "nonce", "response_mode", "prompt", "code_challenge", "code_challenge_method", "id_token_hint", "registration", "display", "login_hint", "ui_locales", "claims_locales", "acr_values":
			var value string
			if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
				return nil, "invalid_request_object"
			}
			merged.Set(name, value)
		default:
			// Unrecognized extensions cannot become login claims or override
			// any security decision. OAuth requires ignoring unknown parameters.
		}
	}
	return merged, ""
}

func oidcRequestObjectPart(encoded string) (map[string]json.RawMessage, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || !utf8.Valid(data) || strings.ContainsAny(encoded, "\r\n") {
		return nil, fmt.Errorf("invalid request object encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("request object requires a JSON object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if _, duplicate := object[name]; !ok || duplicate {
			return nil, fmt.Errorf("duplicate request object member")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		object[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid request object closing delimiter")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing request object data")
	}
	return object, nil
}
