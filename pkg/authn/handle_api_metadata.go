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
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"net/http"
	"time"
)

func (p *Portal) handleAPIMetadata(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	rr.Response.Code = http.StatusOK
	resp := identity.Version()
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}
