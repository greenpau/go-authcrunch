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

package idp

import (
	"encoding/json"
	// "fmt"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/idp/saml"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// IdentityProvider represents identity provider.
type IdentityProvider interface {
	GetRealm() string
	GetName() string
	GetKind() string
	GetDriver() string
	GetConfig() map[string]interface{}
	Configure() error
	Configured() bool
	Request(operator.Type, *requests.Request) error
	GetLoginIcon() *icons.LoginIcon
	GetLogoutURL() string
	GetIdentityTokenCookieName() string
}

// NewIdentityProvider returns IdentityProvider instance.
func NewIdentityProvider(cfg *IdentityProviderConfig, logger *zap.Logger) (IdentityProvider, error) {
	var p IdentityProvider
	var err error

	if logger == nil {
		return nil, errors.ErrIdentityProviderConfigureLoggerNotFound
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	b, _ := json.Marshal(cfg.Params)

	switch cfg.Kind {
	case "oauth":
		config := &oauth.Config{}
		if err := json.Unmarshal(b, config); err != nil {
			return nil, errors.ErrIdentityProviderNewConfig.WithArgs(cfg.Params, err)
		}
		config.Name = cfg.Name
		p, err = oauth.NewIdentityProvider(config, logger)
	case "saml":
		config := &saml.Config{}
		if err := json.Unmarshal(b, config); err != nil {
			return nil, errors.ErrIdentityProviderNewConfig.WithArgs(cfg.Params, err)
		}
		config.Name = cfg.Name
		p, err = saml.NewIdentityProvider(config, logger)
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}
