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

package ids

import (
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/ids/ldap"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// IdentityStore represents identity store.
type IdentityStore interface {
	GetRealm() string
	GetName() string
	GetKind() string
	GetConfig() map[string]interface{}
	Configure() error
	Configured() bool
	Request(operator.Type, *requests.Request) error
	GetLoginIcon() *icons.LoginIcon
}

// NewIdentityStore returns IdentityStore instance.
func NewIdentityStore(cfg *IdentityStoreConfig, logger *zap.Logger) (IdentityStore, error) {
	var st IdentityStore
	var err error

	if logger == nil {
		return nil, errors.ErrIdentityStoreConfigureLoggerNotFound
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	b, _ := json.Marshal(cfg.Params)

	switch cfg.Kind {
	case "local":
		config := &local.Config{}
		if err := json.Unmarshal(b, config); err != nil {
			return nil, errors.ErrIdentityStoreNewConfig.WithArgs(cfg.Params, err)
		}
		config.Name = cfg.Name
		st, err = local.NewIdentityStore(config, logger)
	case "ldap":
		config := &ldap.Config{}
		if err := json.Unmarshal(b, config); err != nil {
			return nil, errors.ErrIdentityStoreNewConfig.WithArgs(cfg.Params, err)
		}
		config.Name = cfg.Name
		st, err = ldap.NewIdentityStore(config, logger)
	}

	if err != nil {
		return nil, err
	}

	return st, nil
}
