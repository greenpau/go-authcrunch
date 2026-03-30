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

package validator

import (
	"encoding/json"
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func (v *TokenValidator) parseUserFromAuthProxyResponse(ar *requests.AuthorizationRequest) (*user.User, error) {
	var userData map[string]any
	if err := json.Unmarshal([]byte(ar.Token.Payload), &userData); err != nil {
		return nil, fmt.Errorf("parseUserFromAuthProxyResponse failed: %v", err)
	}
	// func (u *user.User) GetData() map[string]interface{}
	// usr.Claims.Address
	// usr.Claims.AccessList
	// usr.Claims.AccessList.Paths

	return nil, fmt.Errorf("parseUserFromAuthProxyResponse not implemented: %v", ar.Token.Payload)
}
