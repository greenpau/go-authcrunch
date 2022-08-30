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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	"go.uber.org/zap"
)

// SingleSignOnProvider represents sso provider interface.
type SingleSignOnProvider interface {
	GetName() string
	GetDriver() string
	GetConfig() map[string]interface{}
	Configure() error
	Configured() bool
	GetMetadata() ([]byte, error)
}

// Provider represents sso provider.
type Provider struct {
	config     *SingleSignOnProviderConfig
	configured bool
	logger     *zap.Logger
	cert       *x509.Certificate
	privateKey any
	metadata   []byte
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

	certBytes, err := fileutil.ReadFileBytes(cfg.CertPath)
	if err != nil {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("cert error", err)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock.Type != "CERTIFICATE" {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("unexpected block type", certBlock.Type)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)

	pkBytes, err := fileutil.ReadFileBytes(cfg.PrivateKeyPath)
	if err != nil {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("private key error", err)
	}

	pkBlock, _ := pem.Decode(pkBytes)
	if pkBlock.Type != "PRIVATE KEY" {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("unexpected block type", pkBlock.Type)
	}

	pk, err := x509.ParsePKCS8PrivateKey(pkBlock.Bytes)
	if err != nil {
		return nil, errors.ErrSingleSignOnProviderConfigInvalid.WithArgs("private key parse error", err)
	}

	prv := &Provider{
		config:     cfg,
		logger:     logger,
		cert:       cert,
		privateKey: pk,
	}

	p = prv

	return p, nil
}
