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

	"github.com/greenpau/go-authcrunch/pkg/translate"
)

// Page contains a snapshot for an OIDC browser view. Kind is consent, form_post,
// or error. Renderers must escape its values and preserve form actions, hidden
// fields and decision values. None of these fields supply authentication proof.
// Nonce authorizes the form-post script and the standalone stylesheet only.
type Page struct {
	Language       translate.LangID `json:"-" xml:"-" yaml:"-"`
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
	page := Page{Kind: "consent", Title: o.translate("oidc_consent_title"), ClientName: o.clients[request.clientID].ClientName,
		Username: o.sessions[request.session].username, Action: o.config.Issuer + "/oidc/continue", CSRF: request.consent}
	for _, scope := range request.scopes {
		switch scope {
		case "openid":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_account_identifier"), o.translate("oidc_account_description")})
		case "profile":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_profile_title"), o.translate("oidc_profile_description")})
		case "email":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_email_title"), o.translate("oidc_email_description")})
		case "address":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_address_title"), o.translate("oidc_address_description")})
		case "phone":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_phone_title"), o.translate("oidc_phone_description")})
		case "offline_access":
			page.Permissions = append(page.Permissions, PagePermission{o.translate("oidc_offline_title"), o.translate("oidc_offline_description")})
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
			label := localizedOIDCClaimLabel(name, o.language)
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
	return localizedOIDCClaimLabel(name, translate.English)
}

func localizedOIDCClaimLabel(name string, lang translate.LangID) string {
	labels := map[string]string{
		"sub": "oidc_account_identifier", "name": "oidc_claim_name", "given_name": "oidc_claim_given_name",
		"family_name": "oidc_claim_family_name", "middle_name": "oidc_claim_middle_name", "nickname": "oidc_claim_nickname",
		"preferred_username": "username_label", "profile": "oidc_claim_profile", "picture": "oidc_claim_picture",
		"website": "oidc_claim_website", "gender": "oidc_claim_gender", "birthdate": "oidc_claim_birthdate", "zoneinfo": "oidc_claim_zoneinfo",
		"locale": "oidc_claim_locale", "updated_at": "oidc_claim_updated_at", "email": "oidc_email_title",
		"email_verified": "oidc_claim_email_verified", "address": "oidc_address_title",
		"phone_number": "oidc_phone_title", "phone_number_verified": "oidc_claim_phone_verified",
		"acr": "oidc_claim_acr", "amr": "oidc_claim_amr", "auth_time": "oidc_claim_auth_time",
	}
	if id := labels[name]; id != "" {
		return translate.Translate(id, translate.NormalizeLanguage(string(lang)), nil)
	}
	return name
}

// Translate returns a plain-text browser message using the page language.
func (page Page) Translate(id string) string {
	return translate.Translate(id, translate.NormalizeLanguage(string(page.Language)), nil)
}

// LanguageCode returns the normalized browser page language.
func (page Page) LanguageCode() string {
	return string(translate.NormalizeLanguage(string(page.Language)))
}

// Direction returns the browser page's reading direction.
func (page Page) Direction() string {
	if page.LanguageCode() == "ar" || page.LanguageCode() == "he" {
		return "rtl"
	}
	return "ltr"
}

func (o *Provider) translate(id string) string {
	return translate.Translate(id, translate.NormalizeLanguage(string(o.language)), nil)
}

// Rendering runs after handlers release provider and identity locks. Templates
// cannot delay other sessions, reenter a locked provider, or publish partial HTML.
func (o *Provider) sendResponse(w http.ResponseWriter, r *http.Request, response *oidcHTTPResponse, browserEndpoint bool) {
	if browserEndpoint {
		response.header.Add("Vary", "Accept")
		if response.errorCode != "" && oidcAcceptsHTML(r) {
			page := Page{Kind: "error", Title: o.translate("oidc_error_title"), Message: o.translate("oidc_invalid_request")}
			if response.status == http.StatusServiceUnavailable {
				page.Message = o.translate("oidc_unavailable")
			}
			response.page = &page
		}
	}
	if page := response.page; page != nil {
		page.BasePath, page.Nonce = o.mount, oidcRandom()
		page.Language = o.language
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
