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
	"net/http"
	"strconv"

	"go.uber.org/zap"
)

const jwksPath = "/.well-known/jwks.json"

func (p *Portal) handleHTTPJWKS(w http.ResponseWriter, r *http.Request) error {
	// Key configuration can change on reload, including switching to HMAC.
	p.disableClientCache(w)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	content, err := p.keystore.GetJWKS()
	if err != nil {
		p.logger.Error("Failed to publish portal signing keys", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}
	if len(content) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return nil
	}
	_, err = w.Write(content)
	return err
}
