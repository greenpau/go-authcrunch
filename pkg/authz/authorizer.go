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

package authz

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/http"
)

// Authorizer is an authentication endpoint.
type Authorizer struct {
	Path           string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	GatekeeperName string `json:"gatekeeper_name,omitempty" xml:"gatekeeper_name,omitempty" yaml:"gatekeeper_name,omitempty"`
	logger         *zap.Logger
	gatekeeper     *Gatekeeper
}

// Provision configures the instance of Authorizer.
func (m *Authorizer) Provision(logger *zap.Logger) error {
	m.logger = logger

	gatekeeper, err := gatekeeperRegistry.Lookup(m.GatekeeperName)
	if err != nil {
		return err
	}
	m.gatekeeper = gatekeeper

	m.logger.Info(
		"provisioned authenticator",
		zap.String("gatekeeper_name", m.GatekeeperName),
		zap.String("path", m.Path),
	)
	return nil
}

// Validate validates the provisioning.
func (m *Authorizer) Validate() error {
	m.logger.Info(
		"validated authenticator",
		zap.String("gatekeeper_name", m.GatekeeperName),
		zap.String("path", m.Path),
	)
	return nil
}

// Authenticate authorizes HTTP requests.
func (m *Authorizer) Authenticate(w http.ResponseWriter, r *http.Request, rr *requests.AuthorizationRequest) error {
	if m.gatekeeper == nil {
		m.logger.Warn(
			"Authenticate failed",
			zap.String("gatekeeper_name", m.GatekeeperName),
			zap.Error(errors.ErrGatekeeperUnavailable),
		)
		return errors.ErrGatekeeperUnavailable
	}
	return m.gatekeeper.Authenticate(w, r, rr)
}
