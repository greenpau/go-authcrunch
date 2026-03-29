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

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func (p *Portal) authenticateAPIKeyAuthRequest(_ context.Context, _ http.ResponseWriter, _ *http.Request, rr *requests.Request, realmName, apiKey string) error {
	rr.Key.Payload = apiKey

	backend := p.getIdentityStoreByRealm(realmName)
	if backend == nil {
		rr.Response.Code = http.StatusBadRequest
		return fmt.Errorf("no matching realm found")
	}
	rr.Upstream.Method = backend.GetKind()
	rr.Upstream.Realm = backend.GetRealm()

	if err := backend.Request(operator.LookupAPIKey, rr); err != nil {
		return errors.ErrAPIKeyAuthFailed
	}

	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		rr.Response.Code = http.StatusUnauthorized
		return err
	}

	rr.Response.Code = http.StatusOK
	return nil
}
