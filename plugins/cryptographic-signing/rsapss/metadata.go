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

	"github.com/greenpau/go-authcrunch/pkg/kms"
)

var _ kms.AccessSigner = (*Signer)(nil)

// Metadata attests the immutable configuration used by this initialized signer.
// It performs no file reads and returns no private material. The root's strict
// access profile imposes additional binding checks; standalone Sign retains its
// existing opaque issuer/audience contract.
func (s *Signer) Metadata() (kms.AccessSignerMetadata, error) {
	if s == nil || s.key == nil {
		return kms.AccessSignerMetadata{}, fmt.Errorf("PS256 signer is uninitialized")
	}
	policy := kms.AccessSignerPolicy{
		Algorithm: s.config.Algorithm, KeyID: s.config.KeyID, TokenType: TokenType,
		Issuer: s.config.Issuer, Audience: s.config.Audience,
		MaxLifetimeSeconds: int(s.maxAge),
	}
	// The root-assigned name is excluded from the normalized backend digest.
	// Use the core constructor so metadata and host declarations hash identically.
	config, err := kms.NewExternalAccessSignerConfig("rsapss", "rsapss", policy, s.config)
	if err != nil {
		return kms.AccessSignerMetadata{}, fmt.Errorf("PS256 signer metadata is invalid")
	}
	return kms.AccessSignerMetadata{Kind: config.Kind, ConfigDigest: config.ConfigDigest, Policy: config.Policy}, nil
}
