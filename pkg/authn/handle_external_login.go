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
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Portal) handleHTTPExternalLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, authMethod string) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)

	if strings.Contains(r.URL.Path, "-js-callback") {
		// Intercept callback with Javascript.
		return p.handleJavascriptCallbackIntercept(ctx, w, r)
	}

	authRealm, err := getEndpoint(r.URL.Path, "/"+authMethod+"/")
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	authRealm = strings.Split(authRealm, "/")[0]

	rr.Upstream.Method = authMethod
	rr.Upstream.Realm = authRealm
	rr.Flags.Enabled = true

	p.logger.Debug(
		"External login requested",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("base_url", rr.Upstream.BaseURL),
		zap.String("base_path", rr.Upstream.BasePath),
		zap.String("auth_method", rr.Upstream.Method),
		zap.String("auth_realm", rr.Upstream.Realm),
		zap.Any("request_path", r.URL.Path),
	)

	provider := p.getIdentityProviderByRealm(authRealm)
	if provider == nil {
		p.logger.Warn(
			"Authentication failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "identity provider not found"),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	err = provider.Request(operator.Authenticate, rr)
	if err != nil {
		p.logger.Warn(
			"Authentication failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	switch rr.Response.Code {
	case http.StatusBadRequest:
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	case http.StatusOK:
		p.logger.Info(
			"Successful login",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("auth_method", rr.Upstream.Method),
			zap.String("auth_realm", rr.Upstream.Realm),
			zap.Any("user", rr.Response.Payload),
		)
	case http.StatusFound:
		p.logger.Debug(
			"Redirect to authorization server",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("url", rr.Response.RedirectURL),
		)
		http.Redirect(w, r, rr.Response.RedirectURL, http.StatusFound)
		return nil
	default:
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotImplemented)
	}
	// User authenticated successfully.
	if err := p.authorizeLoginRequest(ctx, w, r, rr); err != nil {
		return p.handleHTTPErrorWithLog(ctx, w, r, rr, rr.Response.Code, err.Error())
	}
	w.WriteHeader(rr.Response.Code)
	return nil
}

func (p *Portal) handleJavascriptCallbackIntercept(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	p.disableClientCache(w)
	w.WriteHeader(200)

	w.Write([]byte(`<html>
  <body>
    <p>Redirecting to authentication endpoint.</p>
    <script>
      let redirectURL = window.location.href;
      const i = redirectURL.indexOf("#");
      if (i < 0) {
        redirectURL = redirectURL.replace('authorization-code-js-callback', 'authorization-code-callback');
        window.location = redirectURL;
      } else {
        redirectURI = redirectURL.slice(0, i).replace('authorization-code-js-callback', 'authorization-code-callback');
        window.location = redirectURI + "?" + redirectURL.slice(i+1);
      }
    </script>
  </body>
</html>`))
	return nil
}
