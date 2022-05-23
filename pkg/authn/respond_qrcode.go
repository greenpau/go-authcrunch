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
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"github.com/skip2/go-qrcode"
	"go.uber.org/zap"
	"net/http"
)

func (p *Portal) handleQRCode(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.injectSessionID(ctx, w, r, rr)
	p.logger.Debug(
		"Received QR code request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("src_ip", addrutil.GetSourceAddress(r)),
		zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
	)
	w.Header().Set("Content-Type", "image/png")

	png, err := qrcode.Encode(util.GetCurrentBaseURL(r)+"/login", qrcode.Medium, 256)
	if err != nil {
		return p.handleHTTPRenderPlainText(ctx, w, http.StatusInternalServerError)
	}
	w.Write(png)
	return nil
}
