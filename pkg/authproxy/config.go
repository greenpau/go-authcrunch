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

package authproxy

import (
	"fmt"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Config is a config for an identity provider.
type Config struct {
	Realms map[string]*RealmAuthProxyConfig `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{
		Realms: make(map[string]*RealmAuthProxyConfig),
	}
}

// HasRealm returns true if realm is supported.
func (cfg *Config) HasRealm(realmName string) bool {
	_, found := cfg.Realms[realmName]
	return found
}

// HasPortal returns true if there is realm with the provided portal name.
func (cfg *Config) HasPortal(portalName string) bool {
	if portalName == "" {
		return false
	}
	for _, realmCfg := range cfg.Realms {
		if realmCfg.PortalName == portalName {
			return true
		}
	}
	return false
}

// AddAuthenticator adds Authenticator associated with the realm.
func (cfg *Config) AddAuthenticator(portalName string, authenticator Authenticator) error {
	if portalName == "" {
		return fmt.Errorf("portal name is empty")
	}

	found := false
	for _, realmCfg := range cfg.Realms {
		if realmCfg.PortalName == portalName {
			realmCfg.authenticator = authenticator
			realmCfg.hasAuthenticator = true
			found = true
		}
	}

	if !found {
		return fmt.Errorf("portal name %q was not found in auth proxy config", portalName)
	}
	return nil
}

// GetAuthenticator returns Authenticator associated with the realm.
func (cfg *Config) GetAuthenticator(realmName string) (Authenticator, error) {
	realmCfg, found := cfg.Realms[realmName]
	if !found {
		return nil, fmt.Errorf("realm config not found")
	}
	return realmCfg.authenticator, nil
}

// HasBasicAuth returns true if basic auth is enabled.
func (cfg *Config) HasBasicAuth(realmName string) bool {
	realmCfg, found := cfg.Realms[realmName]
	if !found {
		return false
	}
	return realmCfg.BasicAuthEnabled
}

// HasAPIKeyAuth returns true of API key auth is enabled.
func (cfg *Config) HasAPIKeyAuth(realmName string) bool {
	realmCfg, found := cfg.Realms[realmName]
	if !found {
		return false
	}
	return realmCfg.APIKeyAuthEnabled
}

// ParseConfig parses configuration into an identity provider config
func ParseConfig(lines []string) (*Config, error) {
	cfg := NewConfig()

	if len(lines) == 0 {
		return nil, errors.ErrAuthProxyConfigInvalid.WithArgs("empty config")
	}

	for _, encodedLine := range lines {
		var portalID, realmName string

		arr, err := cfgutil.DecodeArgs(encodedLine)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasPrefix(encodedLine, "basic auth"):
			arr = arr[2:]
		case strings.HasPrefix(encodedLine, "api key auth"):
			arr = arr[3:]
		default:
			return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
		}
		if len(arr) > 0 {
			for {
				if len(arr) == 0 {
					break
				}
				if (len(arr) % 2) > 0 {
					return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
				}
				k := arr[0]
				switch k {
				case "portal":
					portalID = arr[1]
					arr = arr[2:]
				case "realm":
					realmName = arr[1]
					arr = arr[2:]
				default:
					return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
				}
			}
		}

		if portalID == "" {
			return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
		}

		if realmName == "" {
			return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
		}

		realmCfg, exists := cfg.Realms[realmName]
		if !exists {
			realmCfg = NewRealmAuthProxyConfig()
			cfg.Realms[realmName] = realmCfg
		}

		switch {
		case strings.HasPrefix(portalID, "https://"):
			realmCfg.IsRemote = true
			if realmCfg.RemoteAddr != "" && portalID != realmCfg.RemoteAddr {
				return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
			}
			realmCfg.RemoteAddr = portalID
		case strings.HasPrefix(portalID, "http://"):
			return nil, errors.ErrAuthProxyConfigInvalid.WithArgs(encodedLine)
		default:
			realmCfg.IsRemote = false
			realmCfg.PortalName = portalID
		}

		switch {
		case strings.HasPrefix(encodedLine, "basic auth"):
			realmCfg.BasicAuthEnabled = true
		case strings.HasPrefix(encodedLine, "api key auth"):
			realmCfg.APIKeyAuthEnabled = true
		}
	}
	return cfg, nil
}
