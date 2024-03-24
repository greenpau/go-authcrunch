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
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/skip2/go-qrcode"
)

func (p *Portal) handleHTTPProfileMfaBarcode(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if parsedUser == nil {
		if rr.Response.RedirectURL == "" {
			return p.handleHTTPRedirect(ctx, w, r, rr, "/login?redirect_url="+r.RequestURI)
		}
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	endpoint, err := getEndpoint(r.URL.Path, "/barcode")
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}

	qrCodeEncoded := strings.TrimPrefix(endpoint, "/mfa/")
	qrCodeEncoded = strings.TrimSuffix(qrCodeEncoded, ".png")
	codeURI, err := base64.StdEncoding.DecodeString(qrCodeEncoded)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusBadRequest)
	}
	png, err := qrcode.Encode(string(codeURI), qrcode.Medium, 256)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
	return nil
}

func (p *Portal) handleHTTPSandboxMfaBarcode(ctx context.Context, w http.ResponseWriter, _ *http.Request, endpoint string) error {
	qrCodeEncoded := strings.TrimPrefix(endpoint, "/mfa/barcode/")
	qrCodeEncoded = strings.TrimSuffix(qrCodeEncoded, ".png")
	codeURI, err := base64.StdEncoding.DecodeString(qrCodeEncoded)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusBadRequest)
	}
	png, err := qrcode.Encode(string(codeURI), qrcode.Medium, 256)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
	return nil
}
