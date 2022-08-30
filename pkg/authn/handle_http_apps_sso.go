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

package authn

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/sso"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

type assumeRoleEntry struct {
	Name         string
	AccountID    string
	ProviderName string
}

func (p *Portal) handleHTTPAppsSingleSignOn(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)

	if parsedUser == nil {
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.deleteAuthCookies(w, r)
		p.logger.Debug(
			"User session not found, redirect to login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", parsedUser.Claims),
			zap.Error(err),
		)
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	// Parse SSO provider name from URL.
	req, err := sso.ParseRequestURL(r)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}

	// Check whether the requested SSO provider exists.
	provider, err := p.fetchSingleSignOnProvider(req.ProviderName)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}

	roles := fetchSingleSignOnRoles(provider.GetName(), usr)

	switch req.Kind {
	case sso.MetadataRequest:
		return p.handleHTTPAppsSingleSignOnMetadata(ctx, w, r, rr, provider, roles)
	case sso.AssumeRoleRequest:
		return p.handleHTTPAppsSingleSignOnAssumeRole(ctx, w, r, rr, provider, roles, usr)
	case sso.MenuRequest:
		return p.handleHTTPAppsSingleSignOnMenu(ctx, w, r, rr, provider, roles, usr)
	}
	return p.handleHTTPAppsSingleSignOnMenu(ctx, w, r, rr, provider, roles, usr)
}

// handleHTTPAppsSingleSignOnMetadata renders metadata.xml content. It is only available to admin users.
func (p *Portal) handleHTTPAppsSingleSignOnMetadata(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request,
	provider sso.SingleSignOnProvider, roles []*assumeRoleEntry) error {
	metadata, err := provider.GetMetadata()
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write(metadata)
	return nil
}

func (p *Portal) handleHTTPAppsSingleSignOnAssumeRole(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request,
	provider sso.SingleSignOnProvider, roles []*assumeRoleEntry, usr *user.User) error {

	/*
		if strings.Contains(r.URL.Path, "/apps/sso/assume") {
			accountRole, err := getEndpoint(r.URL.Path, "/apps/sso/assume/")
			if err != nil {
				p.logger.Warn(
					"SSO request failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("error", "malformed SSO request"),
				)
			} else {
				assumedRole = true
				arr := strings.SplitN(accountRole, "/", 2)
				if len(arr) != 2 {
					return p.handleHTTPRenderError(ctx, w, r, rr, fmt.Errorf("Malformed SSO request"))
				}
				accountID = arr[0]
				roleName = arr[1]
			}
		}
	*/

	/*
			if assumedRole {
			if (role.Name == roleName) && (role.AccountID == accountID) {
				authorizedRole = true
				p.logger.Debug(
					"SSO assume role request received",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("role_name", roleName),
					zap.String("account_id", accountID),
				)
			}
		}
	*/

	/*
			if assumedRole {
			if !authorizedRole {
				p.logger.Debug(
					"Unauthorized SSO assume role request",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("role_name", roleName),
					zap.String("account_id", accountID),
				)
				return p.handleHTTPRenderError(ctx, w, r, rr, fmt.Errorf("Unauthorized SSO assume role request"))
			}
			p.logger.Debug("Redirecting to SAML endpoint")
		}

	*/

	body := []byte("ASSUME ROLE")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return nil
}

// handleHTTPAppsSingleSignOnMenu renders SSO provider role selection page.
func (p *Portal) handleHTTPAppsSingleSignOnMenu(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request,
	provider sso.SingleSignOnProvider, roles []*assumeRoleEntry, usr *user.User) error {

	resp := p.ui.GetArgs()
	resp.PageTitle = "AWS SSO"
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Data["role_count"] = len(roles)
	resp.Data["roles"] = roles

	content, err := p.ui.Render("apps_sso", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func (p *Portal) fetchSingleSignOnProvider(providerName string) (sso.SingleSignOnProvider, error) {
	for _, provider := range p.ssoProviders {
		if provider.GetName() == providerName {
			return provider, nil
		}
	}
	return nil, fmt.Errorf("provider name not found")
}

func (p *Portal) parseSingleSignOnProviderName() (string, string, error) {
	return "aws", "metadata", nil
}

func fetchSingleSignOnRoles(providerName string, usr *user.User) []*assumeRoleEntry {
	roles := []*assumeRoleEntry{}
	for _, entry := range usr.Claims.Roles {
		arr := strings.Split(entry, "/")
		if len(arr) != 3 {
			continue
		}
		if arr[0] != "aws" {
			continue
		}
		role := &assumeRoleEntry{
			Name:         arr[2],
			AccountID:    arr[1],
			ProviderName: providerName,
		}
		roles = append(roles, role)
	}
	return roles
}
