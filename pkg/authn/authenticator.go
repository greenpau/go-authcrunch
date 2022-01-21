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

package authn

import (
	"context"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/requests"
	"go.uber.org/zap"
	"net/http"
)

// Authenticator is an authentication endpoint.
type Authenticator struct {
	Path       string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	PortalName string `json:"portal_name,omitempty" xml:"portal_name,omitempty" yaml:"portal_name,omitempty"`
	logger     *zap.Logger
	portal     *Portal
}

// Provision configures the instance of Authenticator.
func (m *Authenticator) Provision(logger *zap.Logger) error {
	m.logger = logger

	portal, err := portalRegistry.Lookup(m.PortalName)
	if err != nil {
		return err
	}
	m.portal = portal

	m.logger.Info(
		"provisioned authenticator",
		zap.String("portal_name", m.PortalName),
		zap.String("path", m.Path),
	)
	return nil
}

// Validate validates the provisioning.
func (m *Authenticator) Validate() error {
	m.logger.Info(
		"validated authenticator",
		zap.String("portal_name", m.PortalName),
		zap.String("path", m.Path),
	)
	return nil
}

// ServeHTTP is a gateway for the authentication portal.
func (m *Authenticator) ServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	if m.portal == nil {
		m.logger.Warn(
			"ServeHTTP failed",
			zap.String("portal_name", m.PortalName),
			zap.Error(errors.ErrPortalUnavailable),
		)
		return errors.ErrPortalUnavailable
	}
	return m.portal.ServeHTTP(ctx, w, r, rr)
}
