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
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func (p *Portal) authenticateBasicAuthRequest(_ context.Context, _ http.ResponseWriter, _ *http.Request, rr *requests.Request, realmName, username, password string) error {
	rr.User.Username = username
	rr.User.Password = password
	backend := p.getIdentityStoreByRealm(realmName)
	if backend == nil {
		rr.Response.Code = http.StatusBadRequest
		return fmt.Errorf("no matching realm found")
	}
	rr.Upstream.Method = backend.GetKind()
	rr.Upstream.Realm = backend.GetRealm()
	rr.Flags.Enabled = true

	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		rr.Response.Code = http.StatusUnauthorized
		return err
	}

	if len(rr.User.Challenges) != 1 {
		return fmt.Errorf("detected too many auth challenges")
	}
	if rr.User.Challenges[0] != "password" {
		return fmt.Errorf("detected unsupported auth challenges")
	}
	if err := backend.Request(operator.Authenticate, rr); err != nil {
		rr.Response.Code = http.StatusUnauthorized
		return err
	}
	rr.Response.Code = http.StatusOK
	return nil
}
