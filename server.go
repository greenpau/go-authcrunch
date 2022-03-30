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

package authcrunch

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"go.uber.org/zap"
)

type refMap struct {
	portals           map[string]*authn.Portal
	gatekeepers       map[string]*authz.Gatekeeper
	identityStores    map[string]ids.IdentityStore
	identityProviders map[string]idp.IdentityProvider
}

// Server represents AAA SF server.
type Server struct {
	config            *Config
	portals           []*authn.Portal
	gatekeepers       []*authz.Gatekeeper
	identityStores    []ids.IdentityStore
	identityProviders []idp.IdentityProvider
	nameRefs          refMap
	realmRefs         refMap
	logger            *zap.Logger
}

func newRefMap() refMap {
	return refMap{
		portals:           make(map[string]*authn.Portal),
		gatekeepers:       make(map[string]*authz.Gatekeeper),
		identityStores:    make(map[string]ids.IdentityStore),
		identityProviders: make(map[string]idp.IdentityProvider),
	}
}

// NewServer returns an instance of Server.
func NewServer(config *Config, logger *zap.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	srv := &Server{
		config:    config,
		logger:    logger,
		nameRefs:  newRefMap(),
		realmRefs: newRefMap(),
	}

	for _, cfg := range config.IdentityProviders {
		provider, err := idp.NewIdentityProvider(cfg, logger)
		if err != nil {
			return nil, errors.ErrNewServer.WithArgs("failed initializing identity provider", err)
		}
		if _, exists := srv.nameRefs.identityProviders[provider.GetName()]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate identity provider name", provider.GetName())
		}
		if _, exists := srv.realmRefs.identityProviders[provider.GetRealm()]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate identity provider realm", provider.GetRealm())
		}
		if err := provider.Configure(); err != nil {
			return nil, errors.ErrNewServer.WithArgs("failed configuring identity provider", err)
		}
		srv.nameRefs.identityProviders[provider.GetName()] = provider
		srv.realmRefs.identityProviders[provider.GetRealm()] = provider
		srv.identityProviders = append(srv.identityProviders, provider)
	}

	for _, cfg := range config.IdentityStores {
		store, err := ids.NewIdentityStore(cfg, logger)
		if err != nil {
			return nil, errors.ErrNewServer.WithArgs("failed initializing identity store", err)
		}
		if _, exists := srv.nameRefs.identityStores[store.GetName()]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate identity store name", store.GetName())
		}
		if _, exists := srv.realmRefs.identityStores[store.GetRealm()]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate identity store realm", store.GetRealm())
		}
		if err := store.Configure(); err != nil {
			return nil, errors.ErrNewServer.WithArgs("failed configuring identity store", err)
		}
		srv.nameRefs.identityStores[store.GetName()] = store
		srv.realmRefs.identityStores[store.GetRealm()] = store
		srv.identityStores = append(srv.identityStores, store)
	}

	for _, cfg := range config.AuthenticationPortals {
		params := authn.PortalParameters{
			Config:            cfg,
			Logger:            logger,
			IdentityStores:    srv.identityStores,
			IdentityProviders: srv.identityProviders,
		}
		portal, err := authn.NewPortal(params)
		if err != nil {
			return nil, err
		}

		if _, exists := srv.nameRefs.portals[cfg.Name]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate authentication portal name", cfg.Name)
		}

		srv.nameRefs.portals[cfg.Name] = portal
		srv.portals = append(srv.portals, portal)
	}

	for _, cfg := range config.AuthorizationPolicies {
		gatekeeper, err := authz.NewGatekeeper(cfg, logger)
		if err != nil {
			return nil, err
		}

		if _, exists := srv.nameRefs.gatekeepers[cfg.Name]; exists {
			return nil, errors.ErrNewServer.WithArgs("duplicate authorization policy name", cfg.Name)
		}
		srv.nameRefs.gatekeepers[cfg.Name] = gatekeeper
		srv.gatekeepers = append(srv.gatekeepers, gatekeeper)
	}

	return srv, nil
}

// GetConfig returns Server configuration.
func (srv *Server) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	b, _ := json.Marshal(srv.config)
	json.Unmarshal(b, &m)
	return m
}

// GetPortalByName returns an instance of authn.Portal based on its name.
func (srv *Server) GetPortalByName(s string) (*authn.Portal, error) {
	if portal, exists := srv.nameRefs.portals[s]; exists {
		return portal, nil
	}
	return nil, fmt.Errorf("portal not found")
}

// GetGatekeeperByName returns an instance of authz.Gatekeeper based on its name.
func (srv *Server) GetGatekeeperByName(s string) (*authz.Gatekeeper, error) {
	if gatekeeper, exists := srv.nameRefs.gatekeepers[s]; exists {
		return gatekeeper, nil
	}
	return nil, fmt.Errorf("gatekeeper not found")
}
