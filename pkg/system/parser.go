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

package system

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// EncryptedMessageFooter holds footer of PASETO v4 local token.
type EncryptedMessageFooter struct {
	KeyID string `json:"kid,omitempty" xml:"kid,omitempty" yaml:"kid,omitempty"`
}

// ParseEncryptedMessageFooter parses footer of PASETO v4 local token.
func ParseEncryptedMessageFooter(token string) (*EncryptedMessageFooter, error) {
	header := "v4.local."
	if !strings.HasPrefix(token, header) {
		return nil, fmt.Errorf("invalid token header: expected %s", header)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid token format: expected 4 segments, got %d", len(parts))
	}

	encodedFooter := parts[3]
	var footerRaw []byte
	var err error
	footerRaw, err = base64.RawURLEncoding.DecodeString(encodedFooter)
	if err != nil {
		return nil, fmt.Errorf("failed to decode footer: %w", err)
	}

	var footer EncryptedMessageFooter
	if err := json.Unmarshal(footerRaw, &footer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal footer JSON: %w", err)
	}

	if footer.KeyID == "" {
		return nil, fmt.Errorf("empty kid")
	}

	return &footer, nil
}
