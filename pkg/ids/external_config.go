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

package ids

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ExternalIdentityStoreConfig describes a host-owned configured identity store.
// ConfigDigest binds normalized backend configuration without serializing the
// runtime handle or backend credentials. The host must regenerate this derived
// descriptor after resolving configuration, and supply a matching runtime via
// authcrunch.ServerOptions.IdentityStores. It does not register a factory kind.
type ExternalIdentityStoreConfig struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Kind         string `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Realm        string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty" xml:"config_digest,omitempty" yaml:"config_digest,omitempty"`
}

// NewExternalIdentityStoreConfig binds a validated, normalized serializable
// backend configuration to its identifiers. Parsing and normalization remain
// the backend's responsibility; this constructor opens no runtime resources.
func NewExternalIdentityStoreConfig(name, kind, realm string, backendConfig any) (*ExternalIdentityStoreConfig, error) {
	if backendConfig == nil {
		return nil, fmt.Errorf("external identity store backend configuration is nil")
	}
	data, err := json.Marshal(backendConfig)
	if err != nil || string(data) == "null" {
		return nil, fmt.Errorf("external identity store backend configuration is not serializable")
	}
	digest := sha256.Sum256(data)
	cfg := &ExternalIdentityStoreConfig{Name: name, Kind: kind, Realm: realm, ConfigDigest: hex.EncodeToString(digest[:])}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks the derived descriptor without opening a backend. Built-in
// kinds retain their factory and must not be impersonated by external stores.
func (cfg *ExternalIdentityStoreConfig) Validate() error {
	if cfg == nil {
		return fmt.Errorf("external identity store configuration is nil")
	}
	validText := func(value string, limit int) bool {
		return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
	}
	if !validText(cfg.Name, 128) || !validText(cfg.Realm, 256) || !validText(cfg.Kind, 128) {
		return fmt.Errorf("invalid external identity store identifiers")
	}
	if cfg.Kind == "local" || cfg.Kind == "ldap" {
		return fmt.Errorf("external identity store must not use a built-in kind")
	}
	digest, err := hex.DecodeString(cfg.ConfigDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != cfg.ConfigDigest {
		return fmt.Errorf("invalid external identity store configuration digest")
	}
	return nil
}
