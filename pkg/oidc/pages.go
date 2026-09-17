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
	"context"
	_ "embed" // Enables go:embed for the standalone page template.
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Page contains a snapshot for an OIDC browser view. Kind is consent, form_post,
// or error. Renderers must escape its values and preserve form actions, hidden
// fields and decision values. None of these fields supply authentication proof.
// Nonce authorizes the form-post script and the standalone stylesheet only.
type Page struct {
	Kind           string           `json:"-" xml:"-" yaml:"-"`
	Title          string           `json:"-" xml:"-" yaml:"-"`
	Message        string           `json:"-" xml:"-" yaml:"-"`
	BasePath       string           `json:"-" xml:"-" yaml:"-"`
	ClientName     string           `json:"-" xml:"-" yaml:"-"`
	Username       string           `json:"-" xml:"-" yaml:"-"`
	Permissions    []PagePermission `json:"-" xml:"-" yaml:"-"`
	UserInfoClaims []string         `json:"-" xml:"-" yaml:"-"`
	IDTokenClaims  []string         `json:"-" xml:"-" yaml:"-"`
	Action         string           `json:"-" xml:"-" yaml:"-"`
	CSRF           string           `json:"-" xml:"-" yaml:"-"`
	Values         url.Values       `json:"-" xml:"-" yaml:"-"`
	Nonce          string           `json:"-" xml:"-" yaml:"-"`
}

// PagePermission describes a requested scope in language suitable for consent.
type PagePermission struct {
	Title       string `json:"-" xml:"-" yaml:"-"`
	Description string `json:"-" xml:"-" yaml:"-"`
}

//go:embed page.template
var oidcPageTemplate string

func newPageRenderer() (func(context.Context, Page) ([]byte, error), error) {
	t, err := template.New("oidc").Parse(oidcPageTemplate)
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, page Page) ([]byte, error) {
		var buf bytes.Buffer
		if err := t.Execute(&buf, page); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}, nil
}

func (o *Provider) consentPage(w *oidcHTTPResponse, _ *http.Request, request *oidcAuthorization) {
	page := Page{Kind: "consent", Title: "Authorize application", ClientName: o.clients[request.clientID].ClientName,
		Username: o.sessions[request.session].username, Action: o.config.Issuer + "/oidc/continue", CSRF: request.consent}
	for _, scope := range request.scopes {
		switch scope {
		case "openid":
			page.Permissions = append(page.Permissions, PagePermission{"Account identifier", "Recognize your account when you sign in."})
		case "profile":
			page.Permissions = append(page.Permissions, PagePermission{"Profile information", "Access your name, username, and other profile details you have provided."})
		case "email":
			page.Permissions = append(page.Permissions, PagePermission{"Email address", "Access your email address and its verification status."})
		case "address":
			page.Permissions = append(page.Permissions, PagePermission{"Postal address", "Access the postal address you have provided."})
		case "phone":
			page.Permissions = append(page.Permissions, PagePermission{"Phone number", "Access your phone number and its verification status."})
		case "offline_access":
			page.Permissions = append(page.Permissions, PagePermission{"Continued access", "Keep accessing this information until your session expires or access is revoked, even when you are away."})
		}
	}
	for location, claims := range request.claims {
		for name := range claims {
			// UserInfo scope permissions already describe these disclosures.
			covered := name == "sub" && slices.Contains(request.scopes, "openid")
			for _, scope := range request.scopes {
				covered = covered || slices.Contains(oidcScopeClaims[scope], name)
			}
			if location == "userinfo" && covered {
				continue
			}
			label := oidcClaimLabel(name)
			if location == "userinfo" {
				page.UserInfoClaims = append(page.UserInfoClaims, label)
			}
			if location == "id_token" {
				page.IDTokenClaims = append(page.IDTokenClaims, label)
			}
		}
	}
	slices.Sort(page.UserInfoClaims)
	slices.Sort(page.IDTokenClaims)
	w.page = &page
	// The callback was already matched to this client. Chrome also applies
	// form-action to the redirect after a same-origin consent submission.
	target, _ := url.Parse(request.redirectURI)
	w.formActionOrigin = target.Scheme + "://" + target.Host
}

func oidcClaimLabel(name string) string {
	labels := map[string]string{
		"sub": "Account identifier", "name": "Full name", "given_name": "Given name",
		"family_name": "Family name", "middle_name": "Middle name", "nickname": "Nickname",
		"preferred_username": "Username", "profile": "Profile page", "picture": "Profile picture",
		"website": "Website", "gender": "Gender", "birthdate": "Birth date", "zoneinfo": "Time zone",
		"locale": "Language", "updated_at": "Profile update time", "email": "Email address",
		"email_verified": "Email verification status", "address": "Postal address",
		"phone_number": "Phone number", "phone_number_verified": "Phone verification status",
		"acr": "Sign-in assurance", "amr": "Sign-in methods", "auth_time": "Sign-in time",
	}
	if label := labels[name]; label != "" {
		return label
	}
	return name
}

// Rendering runs after handlers release provider and identity locks. Templates
// cannot delay other sessions, reenter a locked provider, or publish partial HTML.
func (o *Provider) sendResponse(w http.ResponseWriter, r *http.Request, response *oidcHTTPResponse, browserEndpoint bool) {
	if browserEndpoint {
		response.header.Add("Vary", "Accept")
		if response.errorCode != "" && oidcAcceptsHTML(r) {
			page := Page{Kind: "error", Title: "Unable to continue", Message: "This sign-in request is invalid or has expired. Return to the application and start signing in again."}
			if response.status == http.StatusServiceUnavailable {
				page.Message = "Sign-in is temporarily unavailable. Return to the application and try again shortly."
			}
			response.page = &page
		}
	}
	if page := response.page; page != nil {
		page.BasePath, page.Nonce = o.mount, oidcRandom()
		policy := "default-src 'none'; style-src 'self' 'nonce-" + page.Nonce + "'; img-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
		if page.Kind == "consent" {
			// no-referrer serializes a native form POST's Origin as null.
			// same-origin retains the origin needed by the existing CSRF check,
			// while withholding the Referer on navigation to the relying party.
			policy += " " + response.formActionOrigin
		}
		if page.Kind == "form_post" {
			target, _ := url.Parse(page.Action)
			policy = fmt.Sprintf("default-src 'none'; style-src 'self' 'nonce-%s'; img-src 'self'; font-src 'self'; script-src 'nonce-%s'; frame-ancestors 'none'; base-uri 'none'; form-action %s://%s", page.Nonce, page.Nonce, target.Scheme, target.Host)
		}
		body, err := o.renderPage(r.Context(), *page)
		response.body.Reset()
		if err != nil {
			// Rendering errors may contain values from a custom template. Never
			// expose them, its partial output, or a newly issued credential.
			response.status = 0
			oidcError(response, http.StatusInternalServerError, "server_error")
		} else {
			if page.Kind == "consent" {
				response.header.Set("Referrer-Policy", "same-origin")
			}
			response.header.Set("Content-Security-Policy", policy)
			response.header.Set("Content-Type", "text/html; charset=utf-8")
			_, _ = response.body.Write(body)
		}
	}
	if r.Method == http.MethodHead {
		response.body.Reset()
	}
	response.send(w)
}

// Only explicit HTML acceptance changes browser endpoint errors. API clients,
// wildcard Accept headers and token/UserInfo endpoints retain JSON responses.
func oidcAcceptsHTML(r *http.Request) bool {
	var htmlQuality, jsonQuality float64
	for entry := range strings.SplitSeq(strings.Join(r.Header.Values("Accept"), ","), ",") {
		kind, params, err := mime.ParseMediaType(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		quality := 1.0
		if raw, ok := params["q"]; ok {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil || !(quality >= 0 && quality <= 1) {
				continue
			}
		}
		switch kind {
		case "text/html":
			htmlQuality = max(htmlQuality, quality)
		case "application/json":
			jsonQuality = max(jsonQuality, quality)
		}
	}
	return htmlQuality > 0 && htmlQuality >= jsonQuality
}
