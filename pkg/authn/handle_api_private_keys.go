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

package authn

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const privateKeysPath = "/api/server/private_keys"

func (p *Portal) handleAPIFetchPrivateKeys(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	p.disableClientCache(w)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if p.config.API == nil || !p.config.API.AdminEnabled || !p.config.API.AdminFetchPrivateKeysEnabled {
		return p.handleJSONError(ctx, w, http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	if err := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated); err != nil {
		return p.handleJSONError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		return p.handleJSONError(ctx, w, http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["format"]) > 1 || len(query["encoding"]) > 1 ||
		(query.Has("format") && query.Get("format") == "") || (query.Has("encoding") && query.Get("encoding") == "") {
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "malformed or repeated private key format/encoding parameter")
	}
	content, err := p.keystore.GetJWKSPrivateKeys(query.Get("format"), query.Get("encoding"))
	if err != nil {
		if errors.Is(err, autherrors.ErrPrivateKeyExportFormat) || errors.Is(err, autherrors.ErrPrivateKeyExportEncoding) || errors.Is(err, autherrors.ErrPrivateKeyExportKeyType) {
			return p.handleJSONError(ctx, w, http.StatusBadRequest, err.Error())
		}
		p.logger.Error("Failed to export portal private signing keys", zap.Error(err))
		return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	if len(content) == 0 {
		return p.handleJSONError(ctx, w, http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(content)
	return err
}
