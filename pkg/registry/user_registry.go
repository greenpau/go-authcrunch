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

package registry

import (
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// LocaUserRegistry is a local registry.
type LocaUserRegistry struct {
	db     *identity.Database
	config *UserRegistryConfig
	cache  *RegistrationCache
	logger *zap.Logger
}

// UserRegistry represents user registry.
type UserRegistry interface {
	// GetRealm() string
	GetName() string
	GetConfig() map[string]interface{}
	// Configure() error
	// Configured() bool
	AddUser(*requests.Request) error
	GetRegistrationEntry(string) (map[string]string, error)
	DeleteRegistrationEntry(string) error
	AddRegistrationEntry(string, map[string]string) error

	GetUsernamePolicyRegex() string
	GetUsernamePolicySummary() string
	GetPasswordPolicyRegex() string
	GetPasswordPolicySummary() string

	GetTitle() string
	GetCode() string
	GetRequireAcceptTerms() bool
	GetTermsConditionsLink() string
	GetPrivacyPolicyLink() string

	GetEmailProvider() string
	GetRequireDomainMailRecord() bool
	GetAdminEmails() []string

	Notify(map[string]string) error
	GetIdentityStoreName() string
}

// NewUserRegistry returns UserRegistry instance.
func NewUserRegistry(cfg *UserRegistryConfig, logger *zap.Logger) (UserRegistry, error) {
	var r UserRegistry
	var err error

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		return nil, errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, errors.ErrUserRegistryConfigureLoggerNotFound)
	}

	db, err := identity.NewDatabase(cfg.Dropbox)
	if err != nil {
		return nil, errors.ErrUserRegistrationConfig.WithArgs(cfg.Name, err)
	}

	localRegistry := &LocaUserRegistry{
		db:     db,
		config: cfg,
		logger: logger,
		cache:  NewRegistrationCache(),
	}

	localRegistry.cache.Run()

	r = localRegistry
	return r, nil
}

// GetConfig returns user registry configuration.
func (r *LocaUserRegistry) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	j, _ := json.Marshal(r.config)
	json.Unmarshal(j, &m)
	return m
}

// GetName returns the uid of the user registry.
func (r *LocaUserRegistry) GetName() string {
	return r.config.Name
}

// AddUser adds user to the user registry.
func (r *LocaUserRegistry) AddUser(rr *requests.Request) error {
	return r.db.AddUser(rr)
}

// GetRegistrationEntry returns a registration entry by id.
func (r *LocaUserRegistry) GetRegistrationEntry(s string) (map[string]string, error) {
	return r.cache.Get(s)
}

// DeleteRegistrationEntry deleted a registration entry by id.
func (r *LocaUserRegistry) DeleteRegistrationEntry(s string) error {
	return r.cache.Delete(s)
}

// AddRegistrationEntry adds a registration entry.
func (r *LocaUserRegistry) AddRegistrationEntry(s string, entry map[string]string) error {
	return r.cache.Add(s, entry)
}

// GetUsernamePolicyRegex returns username policy regular expression.
func (r *LocaUserRegistry) GetUsernamePolicyRegex() string {
	return r.db.GetUsernamePolicyRegex()
}

// GetUsernamePolicySummary returns username policy summary.
func (r *LocaUserRegistry) GetUsernamePolicySummary() string {
	return r.db.GetUsernamePolicySummary()
}

// GetPasswordPolicyRegex returns password policy regular expression.
func (r *LocaUserRegistry) GetPasswordPolicyRegex() string {
	return r.db.GetPasswordPolicyRegex()
}

// GetPasswordPolicySummary returns password policy summary.
func (r *LocaUserRegistry) GetPasswordPolicySummary() string {
	return r.db.GetPasswordPolicySummary()
}

// GetTitle returns the title of signup page.
func (r *LocaUserRegistry) GetTitle() string {
	return r.config.Title
}

// GetCode returns authorization code.
func (r *LocaUserRegistry) GetCode() string {
	return r.config.Code
}

// GetRequireAcceptTerms returns true if the acceptance of terms is required.
func (r *LocaUserRegistry) GetRequireAcceptTerms() bool {
	return r.config.RequireAcceptTerms
}

// GetTermsConditionsLink returns the terms and conditions link.
func (r *LocaUserRegistry) GetTermsConditionsLink() string {
	return r.config.TermsConditionsLink
}

// GetPrivacyPolicyLink returns the privacy policy link.
func (r *LocaUserRegistry) GetPrivacyPolicyLink() string {
	return r.config.PrivacyPolicyLink
}

// GetAdminEmails returns admin email addresses.
func (r *LocaUserRegistry) GetAdminEmails() []string {
	return r.config.AdminEmails
}

// GetEmailProvider returns email provider name.
func (r *LocaUserRegistry) GetEmailProvider() string {
	return r.config.EmailProvider
}

// GetRequireDomainMailRecord returns true if MX record requires validation.
func (r *LocaUserRegistry) GetRequireDomainMailRecord() bool {
	return r.config.RequireDomainMailRecord
}

// GetIdentityStoreName returns associated identity store name.
func (r *LocaUserRegistry) GetIdentityStoreName() string {
	return r.config.IdentityStore
}
