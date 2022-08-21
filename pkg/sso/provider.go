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

package sso

import (
	"encoding/json"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"go.uber.org/zap"
)

// SingleSignOnProvider represents sso provider interface.
type SingleSignOnProvider interface {
	GetName() string
	GetDriver() string
	GetConfig() map[string]interface{}
	Configure() error
	Configured() bool
	GetMetadata() []byte
}

// Provider represents sso provider.
type Provider struct {
	config     *SingleSignOnProviderConfig
	configured bool
	logger     *zap.Logger
}

// GetName return the name associated with sso provider.
func (p *Provider) GetName() string {
	return p.config.Name
}

// GetDriver returns the name of the driver associated with the provider.
func (p *Provider) GetDriver() string {
	return p.config.Driver
}

// GetConfig returns sso provider configuration.
func (p *Provider) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	j, _ := json.Marshal(p.config)
	json.Unmarshal(j, &m)
	return m
}

// Configured returns true if the sso provider was configured.
func (p *Provider) Configured() bool {
	return p.configured
}

// Configure configures sso provider.
func (p *Provider) Configure() error {
	p.configured = true
	return nil
}

// NewSingleSignOnProvider returns SingleSignOnProvider instance.
func NewSingleSignOnProvider(cfg *SingleSignOnProviderConfig, logger *zap.Logger) (SingleSignOnProvider, error) {
	var p SingleSignOnProvider

	if logger == nil {
		return nil, errors.ErrSingleSignOnProviderConfigureLoggerNotFound
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	prv := &Provider{
		config: cfg,
		logger: logger,
	}

	p = prv

	return p, nil
}

// GetMetadata returns the contents of metadata.xml.
func (p *Provider) GetMetadata() []byte {
	return []byte("METADATA")
}
