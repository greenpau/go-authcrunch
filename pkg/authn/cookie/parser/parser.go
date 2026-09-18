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

// Package parser decodes reusable portal cookie directives.
package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewCookieConfigFromDirectives parses complete "cookie ..." statements encoded
// with cfgutil.EncodeArgs, without braces. Collect all statements before calling
// it; the host owns tokenization and placeholder expansion. An empty list returns
// ordinary AUTHP defaults. The result is fresh and validated, ready for
// PortalConfig.ConfigureCookies or cookie.NewFactory.
//
// "cookie prefix <value>" covers every role, including OIDC session/request IDs.
// "cookie <role> name <value>" overrides a name: roles are session id, referer,
// sandbox id, identity token, access token, refresh token, oidc session id, and
// oidc request id, and saml session id. "redirect url" aliases referer; "id token" aliases identity
// token. Explicit names win regardless of statement order, even names equal to
// an old default. Each prefix/name setting occurs once across aliases.
//
// Attributes are "cookie path <value>", "cookie lifetime <seconds>",
// "cookie same site <lax|strict|none>" (also "samesite"), and "cookie
// <insecure|strip domain|guess domain> <enabled|disabled>". A domain entry uses
// "cookie domain <hostname>" and may set per-domain path, lifetime, same site,
// insecure, or strip domain by appending that attribute. Domain precedence is
// declaration order. Each attribute occurs once per global/domain scope.
//
// Reject empty tokens before encoding; EncodeArgs may trim a trailing empty
// field. Quoted values retain their token boundaries. Unknown, duplicate, empty,
// multiline, and malformed settings return nil and an error without raw values.
// Config.Validate owns normalization and semantic checks; parsing starts no
// runtime, accesses no files/network, and never mutates the input statements.
func NewCookieConfigFromDirectives(statements []string) (*cookie.Config, error) {
	config := &cookie.Config{}
	fields := nameFields(config)
	names := make(map[string]string)
	seen := make(map[string]bool)
	prefix := cookie.DefaultCookieNamePrefix
	for i, statement := range statements {
		line := i + 1
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid cookie directive at line %d", line)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 || args[0] != "cookie" || slices.Contains(args, "") {
			return nil, fmt.Errorf("invalid cookie directive at line %d", line)
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return nil, fmt.Errorf("empty cookie argument at line %d", line)
			}
		}
		args = args[1:]
		if args[0] == "prefix" {
			if len(args) != 2 || seen["prefix"] {
				return nil, fmt.Errorf("invalid or duplicate cookie prefix at line %d", line)
			}
			seen["prefix"], prefix = true, args[1]
			continue
		}
		if len(args) >= 3 && args[len(args)-2] == "name" {
			key := strings.Join(args[:len(args)-2], " ")
			// Joining is only used for lookup; check original keyword boundaries.
			if !slices.Equal(strings.Split(key, " "), args[:len(args)-2]) {
				return nil, fmt.Errorf("invalid cookie name keywords at line %d", line)
			}
			switch key {
			case "redirect url":
				key = "referer"
			case "id token":
				key = "identity token"
			}
			if fields[key] == nil || seen["name/"+key] {
				return nil, fmt.Errorf("unknown or duplicate cookie name setting at line %d", line)
			}
			seen["name/"+key], names[key] = true, args[len(args)-1]
			continue
		}
		if args[0] == "domain" {
			if len(args) < 2 {
				return nil, fmt.Errorf("missing cookie domain at line %d", line)
			}
			domain := strings.ToLower(strings.TrimPrefix(args[1], "."))
			if config.Domains == nil {
				config.Domains = make(map[string]*cookie.DomainConfig)
			}
			entry := config.Domains[domain]
			if entry == nil {
				entry = &cookie.DomainConfig{Domain: domain, Seq: len(config.Domains)}
				config.Domains[domain] = entry
			}
			if len(args) == 2 {
				if seen["domain/"+domain] {
					return nil, fmt.Errorf("duplicate cookie domain at line %d", line)
				}
				seen["domain/"+domain] = true
				continue
			}
			if err := applyAttribute(args[2:], attributes{path: &entry.Path, lifetime: &entry.Lifetime, sameSite: &entry.SameSite, insecure: &entry.Insecure, strip: &entry.StripDomainEnabled}, seen, "domain/"+domain+"/", line); err != nil {
				return nil, err
			}
			continue
		}
		if err := applyAttribute(args, attributes{path: &config.Path, lifetime: &config.Lifetime, sameSite: &config.SameSite, insecure: &config.Insecure, strip: &config.StripDomainEnabled, guess: &config.GuessDomainEnabled}, seen, "global/", line); err != nil {
			return nil, err
		}
	}
	if err := config.SetCookieNamePrefix(prefix); err != nil {
		return nil, fmt.Errorf("invalid cookie prefix")
	}
	for key, name := range names {
		*fields[key] = name
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cookie configuration")
	}
	return config, nil
}

func nameFields(c *cookie.Config) map[string]*string {
	return map[string]*string{
		"session id": &c.SessionIDCookieName, "referer": &c.RefererCookieName,
		"sandbox id": &c.SandboxIDCookieName, "identity token": &c.IdentityTokenCookieName,
		"access token": &c.AccessTokenCookieName, "refresh token": &c.RefreshTokenCookieName,
		"oidc session id": &c.OIDCSessionIDCookieName, "oidc request id": &c.OIDCRequestIDCookieName,
		"saml session id": &c.SAMLSessionIDCookieName,
	}
}

type attributes struct {
	path, sameSite         *string
	lifetime               *int
	insecure, strip, guess *bool
}

func applyAttribute(args []string, fields attributes, seen map[string]bool, scope string, line int) error {
	if len(args) < 2 {
		return fmt.Errorf("missing cookie attribute value at line %d", line)
	}
	key := strings.Join(args[:len(args)-1], " ")
	if !slices.Equal(strings.Split(key, " "), args[:len(args)-1]) {
		return fmt.Errorf("invalid cookie attribute keywords at line %d", line)
	}
	if key == "samesite" {
		key = "same site"
	}
	if seen[scope+key] {
		return fmt.Errorf("duplicate cookie attribute at line %d", line)
	}
	seen[scope+key] = true
	value := args[len(args)-1]
	var state *bool
	switch key {
	case "path":
		*fields.path = value
	case "same site":
		*fields.sameSite = value
	case "lifetime":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid cookie lifetime at line %d", line)
		}
		*fields.lifetime = n
	case "insecure":
		state = fields.insecure
	case "strip domain":
		state = fields.strip
	case "guess domain":
		if fields.guess == nil {
			return fmt.Errorf("unsupported cookie domain attribute at line %d", line)
		}
		state = fields.guess
	default:
		return fmt.Errorf("unsupported cookie attribute at line %d", line)
	}
	if state != nil {
		if value != "enabled" && value != "disabled" {
			return fmt.Errorf("cookie state requires enabled or disabled at line %d", line)
		}
		*state = value == "enabled"
	}
	return nil
}
