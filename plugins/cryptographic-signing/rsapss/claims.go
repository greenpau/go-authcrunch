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

package rsapss

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/internal/accessclaims"
)

// Share the bounded exact JSON envelope with the strict access verifier while
// retaining the signer's established sanitized failure contract.
func encodeClaims(claims map[string]any) ([]byte, map[string]any, error) {
	payload, snapshot, err := accessclaims.Encode(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("PS256 signing claims have invalid JSON type or size")
	}
	return payload, snapshot, nil
}
