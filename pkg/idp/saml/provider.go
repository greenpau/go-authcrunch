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

package saml

import (
	"context"
	"encoding/json"
	"encoding/xml"
	samllib "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	providerKind = "saml"
)

// IdentityProvider represents SAML-based identity provider.
type IdentityProvider struct {
	config           *Config `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	serviceProviders map[string]*samllib.ServiceProvider
	idpMetadataURL   *url.URL
	// loginURL is the link to Azure AD authentication portal.
	// The link is auto-generated based on Azure AD tenant and
	// application IDs.
	loginURL   string
	logger     *zap.Logger
	configured bool
}

// NewIdentityProvider return an instance of IdentityProvider.
func NewIdentityProvider(cfg *Config, logger *zap.Logger) (*IdentityProvider, error) {
	if logger == nil {
		return nil, errors.ErrIdentityProviderConfigureLoggerNotFound
	}

	b := &IdentityProvider{
		config: cfg,
		logger: logger,
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	return b, nil
}

// GetRealm return authentication realm.
func (b *IdentityProvider) GetRealm() string {
	return b.config.Realm
}

// GetName return the name associated with this identity provider.
func (b *IdentityProvider) GetName() string {
	return b.config.Name
}

// GetKind returns the authentication method associated with this identity provider.
func (b *IdentityProvider) GetKind() string {
	return providerKind
}

// Configured returns true if the identity provider was configured.
func (b *IdentityProvider) Configured() bool {
	return b.configured
}

// Request performs the requested identity provider operation.
func (b *IdentityProvider) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	}
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// GetConfig returns IdentityProvider configuration.
func (b *IdentityProvider) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	j, _ := json.Marshal(b.config)
	json.Unmarshal(j, &m)
	return m
}

// Configure configures IdentityProvider.
func (b *IdentityProvider) Configure() error {
	b.loginURL = b.config.IdpLoginURL

	idpSignCert, err := fileutil.ReadCertFile(b.config.IdpSignCertLocation)
	if err != nil {
		return err
	}

	// Obtain SAML IdP Metadata
	opts := samlsp.Options{}
	if strings.HasPrefix(b.config.IdpMetadataLocation, "http") {
		idpMetadataURL, err := url.Parse(b.config.IdpMetadataLocation)
		if err != nil {
			return err
		}
		b.idpMetadataURL = idpMetadataURL
		opts.URL = *idpMetadataURL
		idpMetadata, err := samlsp.FetchMetadata(
			context.Background(),
			http.DefaultClient,
			*idpMetadataURL,
		)
		if err != nil {
			return err
		}
		opts.IDPMetadata = idpMetadata
	} else {
		metadataFileContent, err := ioutil.ReadFile(b.config.IdpMetadataLocation)
		if err != nil {
			return err
		}
		idpMetadata, err := samlsp.ParseMetadata(metadataFileContent)
		if err != nil {
			return err
		}
		opts.IDPMetadata = idpMetadata
	}

	b.serviceProviders = make(map[string]*samllib.ServiceProvider)
	for _, acsURL := range b.config.AssertionConsumerServiceURLs {
		sp := samlsp.DefaultServiceProvider(opts)
		sp.AllowIDPInitiated = true
		//sp.EntityID = sp.IDPMetadata.EntityID

		cfgAcsURL, _ := url.Parse(acsURL)
		sp.AcsURL = *cfgAcsURL

		entityID, _ := url.Parse(b.config.EntityID)
		sp.MetadataURL = *entityID

		if b.idpMetadataURL != nil {
			sp.MetadataURL = *b.idpMetadataURL
		}

		for i := range sp.IDPMetadata.IDPSSODescriptors {
			idpSSODescriptor := &sp.IDPMetadata.IDPSSODescriptors[i]
			keyDescriptor := &samllib.KeyDescriptor{
				Use: "signing",
				KeyInfo: samllib.KeyInfo{
					XMLName: xml.Name{
						Space: "http://www.w3.org/2000/09/xmldsig#",
						Local: "KeyInfo",
					},
					// Certificate: idpSignCert,
					X509Data: samllib.X509Data{
						X509Certificates: []samllib.X509Certificate{
							{Data: idpSignCert},
						},
					},
				},
			}
			idpSSODescriptor.KeyDescriptors = append(idpSSODescriptor.KeyDescriptors, *keyDescriptor)
			break
		}

		b.serviceProviders[acsURL] = &sp
	}

	b.logger.Info(
		"successfully configured SAML identity provider",
		zap.String("tenant_id", b.config.TenantID),
		zap.String("application_id", b.config.ApplicationID),
		zap.String("application_name", b.config.ApplicationName),
		zap.Any("acs_urls", b.config.AssertionConsumerServiceURLs),
		zap.String("login_url", b.loginURL),
		zap.String("idp_sign_cert_location", b.config.IdpSignCertLocation),
		zap.String("idp_metadata_location", b.config.IdpMetadataLocation),
		zap.Any("login_icon", b.config.LoginIcon),
	)

	b.configured = true

	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityProvider) GetLoginIcon() *icons.LoginIcon {
	return b.config.LoginIcon
}

// GetLogoutURL returns the logout URL associated with the provider.
func (b *IdentityProvider) GetLogoutURL() string {
	return ""
}

// GetDriver returns the name of the driver associated with the provider.
func (b *IdentityProvider) GetDriver() string {
	return b.config.Driver
}

// GetIdentityTokenCookieName returns the name of the identity token cookie associated with the provider.
func (b *IdentityProvider) GetIdentityTokenCookieName() string {
	return ""
}
