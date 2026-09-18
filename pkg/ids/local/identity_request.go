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

package local

import (
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// RequestWithIdentity performs a self-service operation bound to the current
// local identity represented by the request's authentication evidence.
func (b *IdentityStore) RequestWithIdentity(op operator.Type, r *requests.Request) error {
	b.authenticator.mux.Lock()
	defer b.authenticator.mux.Unlock()
	return b.authenticator.db.RequestWithIdentity(op, r)
}
