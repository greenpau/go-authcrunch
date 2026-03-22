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
	"bytes"
	"mime/quotedprintable"
	"strings"
	"text/template"

	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// LocalUserRegistryProviderKindLabel is the label for local user registry provider type.
const LocalUserRegistryProviderKindLabel = "local"

// LocalUserRegistryProvider represents local user registry provider.
type LocalUserRegistryProvider struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	// The title of the registration page
	Title string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	// The mandatory registration code. It is possible adding multiple
	// codes, comma separated.
	Code string `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	// The file path to registration database.
	Dropbox string `json:"dropbox,omitempty" xml:"dropbox,omitempty" yaml:"dropbox,omitempty"`
	// The switch determining whether a user must accept terms and conditions
	RequireAcceptTerms bool `json:"require_accept_terms,omitempty" xml:"require_accept_terms,omitempty" yaml:"require_accept_terms,omitempty"`
	// The switch determining whether the domain associated with an email has
	// a valid MX DNS record.
	RequireDomainMX bool `json:"require_domain_mx,omitempty" xml:"require_domain_mx,omitempty" yaml:"require_domain_mx,omitempty"`
	// The link to terms and conditions document.
	TermsConditionsLink string `json:"terms_conditions_link,omitempty" xml:"terms_conditions_link,omitempty" yaml:"terms_conditions_link,omitempty"`
	// The link to privacy policy document.
	PrivacyPolicyLink string `json:"privacy_policy_link,omitempty" xml:"privacy_policy_link,omitempty" yaml:"privacy_policy_link,omitempty"`
	// The email provider used for the notifications.
	EmailProviderName string `json:"email_provider_name,omitempty" xml:"email_provider_name,omitempty" yaml:"email_provider_name,omitempty"`
	// The email address(es) of portal administrators.
	AdminEmails []string `json:"admin_emails,omitempty" xml:"admin_emails,omitempty" yaml:"admin_emails,omitempty"`
	// The name of the identity store associated with the Config.
	IdentityStoreName string `json:"identity_store_name,omitempty" xml:"identity_store_name,omitempty" yaml:"identity_store_name,omitempty"`
	// The name of the authentication realm of identity store associated with the Config.
	RealmName string `json:"realm_name,omitempty" xml:"realm_name,omitempty" yaml:"realm_name,omitempty"`
	// DomainRestrictions holds the allow and deny rules for domains in email addresses.
	DomainRestrictions []string `json:"domain_restrictions,omitempty" xml:"domain_restrictions,omitempty" yaml:"domain_restrictions,omitempty"`

	credentials *credentials.Config
	messaging   *messaging.Config
	db          *identity.Database
	cache       *RegistrationCache
	logger      *zap.Logger
}

// NewLocalUserRegistryProvider parses instructions and returns LocalUserRegistryProvider.
func NewLocalUserRegistryProvider(instructions []string) (*LocalUserRegistryProvider, error) {
	provider := &LocalUserRegistryProvider{}

	for _, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs(err, instruction)
		}
		switch args[0] {
		case "name":
			if len(args) != 2 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Name = args[1]
		case "title":
			if len(args) != 2 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Title = args[1]
		case "code":
			if len(args) != 2 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Code = args[1]
		case "dropbox":
			if len(args) != 2 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			provider.Dropbox = args[1]
		case "require":
			if len(args) != 3 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			switch strings.Join(args, " ") {
			case "require accept terms":
				provider.RequireAcceptTerms = true
			case "require domain mx":
				provider.RequireDomainMX = true
			default:
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
		case "link":
			if len(args) != 3 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			switch args[1] {
			case "terms":
				provider.TermsConditionsLink = args[2]
			case "privacy":
				provider.PrivacyPolicyLink = args[2]
			default:
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
		case "email":
			if len(args) < 3 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			switch args[1] {
			case "provider":
				provider.EmailProviderName = args[2]
			default:
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
		case "identity":
			if len(args) != 3 && len(args) != 4 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			switch args[1] {
			case "store":
				provider.IdentityStoreName = args[2]
				if len(args) == 4 {
					provider.RealmName = args[3]
				}
			default:
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
		case "admin":
			if len(args) != 3 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			switch args[1] {
			case "email", "emails":
				provider.AdminEmails = args[2:]
			default:
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
		case "allow", "deny":
			provider.DomainRestrictions = append(provider.DomainRestrictions, cfgutil.EncodeArgs(args))
		case "kind":
			if len(args) != 2 {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs(instruction)
			}
			if args[1] != LocalUserRegistryProviderKindLabel {
				return nil, errors.ErrUserRegistryConfigMalformedInstructionKindMismatch.WithArgs(LocalUserRegistryProviderKindLabel, args[1])
			}
		default:
			return nil, errors.ErrUserRegistryConfigMalformedInstructionUnsupportedKey.WithArgs(instruction)
		}
	}
	err := provider.Validate()
	return provider, err
}

// Validate validates EmailProvider configuration.
func (p *LocalUserRegistryProvider) Validate() error {
	if p.Name == "" {
		return errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("name")
	}
	if p.Dropbox == "" {
		return errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("dropbox")
	}
	if p.EmailProviderName == "" {
		return errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("email provider")
	}
	if len(p.AdminEmails) < 1 {
		return errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("admin email address")
	}
	if p.Title == "" {
		p.Title = "Sign Up"
	}
	if p.IdentityStoreName == "" {
		return errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("identity store name")
	}
	if len(p.DomainRestrictions) > 0 {
		_, err := NewDomainRestrictionRuleset(p.DomainRestrictions)
		if err != nil {
			return errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs(p.DomainRestrictions, err)
		}
	}
	return nil
}

// Activate starts LocalUserRegistryProvider.
func (p *LocalUserRegistryProvider) Activate(logger *zap.Logger) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if logger == nil {
		return errors.ErrUserRegistrationConfig.WithArgs(p.Name, errors.ErrUserRegistryConfigureLoggerNotFound)
	}
	p.logger = logger
	db, err := identity.NewDatabase(p.Dropbox)
	if err != nil {
		return errors.ErrUserRegistrationConfig.WithArgs(p.Name, err)
	}
	p.db = db
	p.cache = NewRegistrationCache()
	p.cache.Run()
	return nil
}

// AsMap returns credential config.
func (p *LocalUserRegistryProvider) AsMap() map[string]any {
	m := make(map[string]any)
	if p.Name != "" {
		m["name"] = p.Name
	}
	if p.Title != "" {
		m["title"] = p.Title
	}
	if p.Code != "" {
		m["code"] = p.Code
	}
	if p.Dropbox != "" {
		m["dropbox"] = p.Dropbox
	}
	m["require_accept_terms"] = p.RequireAcceptTerms
	m["require_domain_mx"] = p.RequireDomainMX
	if p.TermsConditionsLink != "" {
		m["terms_conditions_link"] = p.TermsConditionsLink
	}
	if p.PrivacyPolicyLink != "" {
		m["privacy_policy_link"] = p.PrivacyPolicyLink
	}
	if p.EmailProviderName != "" {
		m["email_provider_name"] = p.EmailProviderName
	}
	if len(p.AdminEmails) > 0 {
		m["admin_emails"] = p.AdminEmails
	}
	if p.IdentityStoreName != "" {
		m["identity_store_name"] = p.IdentityStoreName
	}
	if p.RealmName != "" {
		m["realm_name"] = p.RealmName
	}
	if len(p.DomainRestrictions) > 0 {
		m["domain_restrictions"] = p.DomainRestrictions
	}
	m["kind"] = p.Kind()
	return m
}

// Kind returns LocalUserRegistryProvider kind.
func (p *LocalUserRegistryProvider) Kind() string {
	return LocalUserRegistryProviderKindLabel
}

// SetCredentials configures credentials for messaging provider associated with user registration.
func (p *LocalUserRegistryProvider) SetCredentials(cfg *credentials.Config) error {
	p.credentials = cfg
	return nil
}

// SetMessaging configures credentials for messaging associated with user registration.
func (p *LocalUserRegistryProvider) SetMessaging(cfg *messaging.Config) error {
	p.messaging = cfg
	return nil
}

// GetIdentityStoreName returns identity store name associated with LocalUserRegistryProvider
func (p *LocalUserRegistryProvider) GetIdentityStoreName() string {
	return p.IdentityStoreName
}

// GetName returns LocalUserRegistryProvider name
func (p *LocalUserRegistryProvider) GetName() string {
	return p.Name
}

// AddUser adds user to the user registry.
func (p *LocalUserRegistryProvider) AddUser(rr *requests.Request) error {
	return p.db.AddUser(rr)
}

// GetRegistrationEntry returns a registration entry by id.
func (p *LocalUserRegistryProvider) GetRegistrationEntry(s string) (map[string]string, error) {
	return p.cache.Get(s)
}

// DeleteRegistrationEntry deleted a registration entry by id.
func (p *LocalUserRegistryProvider) DeleteRegistrationEntry(s string) error {
	return p.cache.Delete(s)
}

// AddRegistrationEntry adds a registration entry.
func (p *LocalUserRegistryProvider) AddRegistrationEntry(s string, entry map[string]string) error {
	return p.cache.Add(s, entry)
}

// GetUsernamePolicyRegex returns username policy regular expression.
func (p *LocalUserRegistryProvider) GetUsernamePolicyRegex() string {
	return p.db.GetUsernamePolicyRegex()
}

// GetUsernamePolicySummary returns username policy summary.
func (p *LocalUserRegistryProvider) GetUsernamePolicySummary() string {
	return p.db.GetUsernamePolicySummary()
}

// GetPasswordPolicyRegex returns password policy regular expression.
func (p *LocalUserRegistryProvider) GetPasswordPolicyRegex() string {
	return p.db.GetPasswordPolicyRegex()
}

// GetPasswordPolicySummary returns password policy summary.
func (p *LocalUserRegistryProvider) GetPasswordPolicySummary() string {
	return p.db.GetPasswordPolicySummary()
}

// GetTitle returns the title of signup page.
func (p *LocalUserRegistryProvider) GetTitle() string {
	return p.Title
}

// GetCode returns authorization code.
func (p *LocalUserRegistryProvider) GetCode() string {
	return p.Code
}

// GetRequireAcceptTerms returns true if the acceptance of terms is required.
func (p *LocalUserRegistryProvider) GetRequireAcceptTerms() bool {
	return p.RequireAcceptTerms
}

// GetTermsConditionsLink returns the terms and conditions link.
func (p *LocalUserRegistryProvider) GetTermsConditionsLink() string {
	return p.TermsConditionsLink
}

// GetPrivacyPolicyLink returns the privacy policy link.
func (p *LocalUserRegistryProvider) GetPrivacyPolicyLink() string {
	return p.PrivacyPolicyLink
}

// GetAdminEmails returns admin email addresses.
func (p *LocalUserRegistryProvider) GetAdminEmails() []string {
	return p.AdminEmails
}

// GetEmailProvider returns email provider name.
func (p *LocalUserRegistryProvider) GetEmailProvider() string {
	return p.EmailProviderName
}

// GetRequireDomainMX returns true if MX record requires validation.
func (p *LocalUserRegistryProvider) GetRequireDomainMX() bool {
	return p.RequireDomainMX
}

// GetRealmName returns associated identity store name.
func (p *LocalUserRegistryProvider) GetRealmName() string {
	if p.RealmName == "" {
		return p.IdentityStoreName
	}
	return p.RealmName
}

// SetRealmName returns associated identity store name.
func (p *LocalUserRegistryProvider) SetRealmName(realmName string) {
	if p.RealmName != "" {
		return
	}
	p.RealmName = realmName
}

// GetDomainRestrictions returns list of domain restrictions.
func (p *LocalUserRegistryProvider) GetDomainRestrictions() []string {
	return p.DomainRestrictions
}

// Notify serves notifications.
func (p *LocalUserRegistryProvider) Notify(data map[string]string) error {
	var requiredFields []string
	var rcpts []string

	commonRequiredFields := []string{
		"session_id",
		"request_id",
		"timestamp",
		"template",
	}

	if data == nil {
		return errors.ErrNotifyRequestDataNil
	}

	for _, fieldName := range commonRequiredFields {
		if _, exists := data[fieldName]; !exists {
			return errors.ErrNotifyRequestFieldNotFound.WithArgs(fieldName)
		}
	}

	tmplName := data["template"]
	switch tmplName {
	case "registration_confirmation":
		requiredFields = []string{
			"registration_id",
			"username",
			"email",
			"registration_url",
			"registration_code",
			"src_ip",
			"src_conn_ip",
		}
	case "registration_ready":
		requiredFields = []string{
			"registration_id",
			"username",
			"email",
			"registration_url",
			"src_ip",
			"src_conn_ip",
		}
	case "registration_verdict":
		requiredFields = []string{
			"username",
			"email",
			"verdict",
		}
	default:
		return errors.ErrNotifyRequestTemplateUnsupported.WithArgs(tmplName)
	}

	for _, fieldName := range requiredFields {
		if _, exists := data[fieldName]; !exists {
			return errors.ErrNotifyRequestFieldNotFound.WithArgs(fieldName)
		}
	}

	switch tmplName {
	case "registration_confirmation", "registration_verdict":
		rcpts = append(rcpts, data["email"])
	case "registration_ready":
		rcpts = p.AdminEmails
	}

	lang := "en"
	if v, exists := data["lang"]; exists {
		lang = v
	} else {
		data["lang"] = lang
	}

	switch lang {
	case "en":
	default:
		return errors.ErrNotifyRequestLangUnsupported.WithArgs(lang)
	}

	if p.messaging == nil {
		return errors.ErrNotifyRequestMessagingNil.WithArgs(p.EmailProviderName)
	}

	tmplSubjAsset, err := messaging.EmailTemplates.GetAsset(lang + "/" + tmplName + "_subject")
	if err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
	}
	tmplSubj, tmplSubjErr := template.New("email_subj").Parse(tmplSubjAsset.Content)
	if tmplSubjErr != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, tmplSubjErr)
	}
	emailSubj := bytes.NewBuffer(nil)
	if err := tmplSubj.Execute(emailSubj, data); err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
	}

	tmplBodyAsset, err := messaging.EmailTemplates.GetAsset(lang + "/" + tmplName + "_body")
	if err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
	}
	tmplBody, tmplBodyErr := template.New("email_body").Parse(tmplBodyAsset.Content)
	if tmplBodyErr != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, tmplBodyErr)
	}
	emailBody := bytes.NewBuffer(nil)
	if err := tmplBody.Execute(emailBody, data); err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
	}

	var qpEmailBody string
	qpEmailBody, err = quotedPrintableBody(emailBody.String())
	if err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
	}

	qpEmailSubj := emailSubj.String()
	repl := strings.NewReplacer("\r", "", "\n", " ")
	qpEmailSubj = strings.TrimSpace(repl.Replace(qpEmailSubj))

	providerType := p.messaging.GetProviderType(p.EmailProviderName)

	switch providerType {
	case "email":
		provider := p.messaging.ExtractEmailProvider(p.EmailProviderName)
		if provider == nil {
			return errors.ErrNotifyRequestEmailProviderNotFound.WithArgs(p.EmailProviderName)
		}

		providerCredName := p.messaging.FindProviderCredentials(p.EmailProviderName)
		if providerCredName == "" {
			return errors.ErrNotifyRequestEmailProviderCredNotFound.WithArgs(p.EmailProviderName)
		}

		var providerCred *credentials.GenericCredential
		if providerCredName != "passwordless" {
			if p.credentials == nil {
				return errors.ErrNotifyRequestCredNil.WithArgs(p.EmailProviderName)
			}
			providerCred = p.credentials.ExtractGeneric(providerCredName)
			if providerCred == nil {
				return errors.ErrNotifyRequestCredNotFound.WithArgs(p.EmailProviderName, providerCredName)
			}
		}

		if err := provider.Send(&messaging.SendInput{
			Subject:     qpEmailSubj,
			Body:        qpEmailBody,
			Recipients:  rcpts,
			Credentials: providerCred,
		}); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
		}
	case "file":
		provider := p.messaging.ExtractFileProvider(p.EmailProviderName)
		if provider == nil {
			return errors.ErrNotifyRequestEmailProviderNotFound.WithArgs(p.EmailProviderName)
		}
		if err := provider.Send(&messaging.SendInput{
			Subject:    qpEmailSubj,
			Body:       qpEmailBody,
			Recipients: rcpts,
		}); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(p.EmailProviderName, err)
		}
	default:
		return errors.ErrNotifyRequestProviderTypeUnsupported.WithArgs(p.EmailProviderName, providerType)
	}
	return nil
}

func quotedPrintableBody(s string) (string, error) {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}
