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

package identity

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"strings"
	"time"
)

// UserMetadata is metadata associated with a user.
type UserMetadata struct {
	ID           string    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Enabled      bool      `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Username     string    `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Title        string    `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	Name         string    `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Email        string    `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Created      time.Time `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Revision     int       `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	Avatar       string    `json:"avatar,omitempty" xml:"avatar,omitempty" yaml:"avatar,omitempty"`
}

// UserMetadataBundle is a collection of public users.
type UserMetadataBundle struct {
	users []*UserMetadata
	size  int
}

// User is a user identity.
type User struct {
	ID             string          `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Enabled        bool            `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Human          bool            `json:"human,omitempty" xml:"human,omitempty" yaml:"human,omitempty"`
	Username       string          `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Title          string          `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	Name           *Name           `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization   *Organization   `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
	Names          []*Name         `json:"names,omitempty" xml:"names,omitempty" yaml:"names,omitempty"`
	Organizations  []*Organization `json:"organizations,omitempty" xml:"organizations,omitempty" yaml:"organizations,omitempty"`
	StreetAddress  []*Location     `json:"street_address,omitempty" xml:"street_address,omitempty" yaml:"street_address,omitempty"`
	EmailAddress   *EmailAddress   `json:"email_address,omitempty" xml:"email_address,omitempty" yaml:"email_address,omitempty"`
	EmailAddresses []*EmailAddress `json:"email_addresses,omitempty" xml:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
	Passwords      []*Password     `json:"passwords,omitempty" xml:"passwords,omitempty" yaml:"passwords,omitempty"`
	PublicKeys     []*PublicKey    `json:"public_keys,omitempty" xml:"public_keys,omitempty" yaml:"public_keys,omitempty"`
	APIKeys        []*APIKey       `json:"api_keys,omitempty" xml:"api_keys,omitempty" yaml:"api_keys,omitempty"`
	MfaTokens      []*MfaToken     `json:"mfa_tokens,omitempty" xml:"mfa_tokens,omitempty" yaml:"mfa_tokens,omitempty"`
	Lockout        *LockoutState   `json:"lockout,omitempty" xml:"lockout,omitempty" yaml:"lockout,omitempty"`
	Avatar         *Image          `json:"avatar,omitempty" xml:"avatar,omitempty" yaml:"avatar,omitempty"`
	Created        time.Time       `json:"created,omitempty" xml:"created,omitempty" yaml:"created,omitempty"`
	LastModified   time.Time       `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Revision       int             `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	Roles          []*Role         `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Registration   *Registration   `json:"registration,omitempty" xml:"registration,omitempty" yaml:"registration,omitempty"`
	rolesRef       map[string]interface{}
}

// NewUserMetadataBundle returns an instance of UserMetadataBundle.
func NewUserMetadataBundle() *UserMetadataBundle {
	return &UserMetadataBundle{
		users: []*UserMetadata{},
	}
}

// Add adds UserMetadata to UserMetadataBundle.
func (b *UserMetadataBundle) Add(k *UserMetadata) {
	b.users = append(b.users, k)
	b.size++
}

// Get returns UserMetadata instances of the UserMetadataBundle.
func (b *UserMetadataBundle) Get() []*UserMetadata {
	return b.users
}

// Size returns the number of UserMetadata instances in UserMetadataBundle.
func (b *UserMetadataBundle) Size() int {
	return b.size
}

// NewUser returns an instance of User.
func NewUser(s string) *User {
	user := &User{
		ID:           NewID(),
		Username:     s,
		Created:      time.Now().UTC(),
		LastModified: time.Now().UTC(),
	}
	return user
}

// NewUserWithRoles returns User with additional fields.
func NewUserWithRoles(username, password, email, fullName string, roles []string) (*User, error) {
	user := NewUser(username)
	if err := user.AddPassword(password, 0); err != nil {
		return nil, err
	}
	if err := user.AddEmailAddress(email); err != nil {
		return nil, err
	}
	if err := user.AddRoles(roles); err != nil {
		return nil, err
	}
	fullName = strings.TrimSpace(fullName)
	if fullName != "" {
		name, err := ParseName(fullName)
		if err != nil {
			return nil, err
		}
		err = user.AddName(name)
		if err != nil {
			return nil, err
		}
	}
	if err := user.Valid(); err != nil {
		return nil, err
	}
	user.Revision = 0
	return user, nil
}

// Valid returns true if a user conforms to a standard.
func (user *User) Valid() error {
	if len(user.ID) != 36 {
		return errors.ErrUserIDInvalidLength.WithArgs(len(user.ID))
	}
	if user.Username == "" {
		return errors.ErrUsernameEmpty
	}
	if len(user.Passwords) < 1 {
		return errors.ErrUserPasswordNotFound
	}
	return nil
}

// AddPassword returns creates and adds password for a user identity.
func (user *User) AddPassword(s string, keepVersions int) error {
	var passwords []*Password
	password, err := NewPassword(s)
	if err != nil {
		return err
	}

	// Check if the existing password is the same as the one provided.
	if len(user.Passwords) > 0 {
		if user.Passwords[0].Hash == password.Hash {
			return nil
		}
	}

	if keepVersions < 1 {
		keepVersions = 9
	}
	passwords = append(passwords, password)
	if len(user.Passwords) > 0 {
		for i, p := range user.Passwords {
			if !p.Disabled {
				p.Disable()
			}
			passwords = append(passwords, p)
			if i > keepVersions {
				break
			}
		}
	}
	user.Passwords = passwords
	user.Revise()
	return nil
}

// AddEmailAddress returns creates and adds password for a user identity.
func (user *User) AddEmailAddress(s string) error {
	email, err := NewEmailAddress(s)
	if err != nil {
		return err
	}
	if len(user.EmailAddresses) == 0 {
		user.EmailAddress = email
		user.EmailAddresses = append(user.EmailAddresses, email)
		user.Revise()
		return nil
	}
	for _, e := range user.EmailAddresses {
		if email.Address == e.Address {
			return nil
		}
	}
	user.EmailAddresses = append(user.EmailAddresses, email)
	user.Revise()
	return nil
}

// HasEmailAddresses checks whether a user has email address.
func (user *User) HasEmailAddresses() bool {
	if len(user.EmailAddresses) == 0 {
		return false
	}
	return true
}

// HasRoles checks whether a user has a role.
func (user *User) HasRoles() bool {
	if len(user.Roles) == 0 {
		return false
	}
	return true
}

// HasRole checks whether a user has a specific role.
func (user *User) HasRole(s string) bool {
	if len(user.Roles) == 0 {
		return false
	}
	role, err := NewRole(s)
	if err != nil {
		return false
	}

	for _, r := range user.Roles {
		if (r.Name == role.Name) && (r.Organization == role.Organization) {
			return true
		}
	}
	return false
}

// AddRoles adds roles to a user identity.
func (user *User) AddRoles(roles []string) error {
	for _, role := range roles {
		if err := user.AddRole(role); err != nil {
			return err
		}
	}
	return nil
}

// AddRole adds a role to a user identity.
func (user *User) AddRole(s string) error {
	role, err := NewRole(s)
	if err != nil {
		return err
	}
	if len(user.Roles) == 0 {
		user.Roles = append(user.Roles, role)
		user.Revise()
		return nil
	}
	for _, r := range user.Roles {
		if (r.Name == role.Name) && (r.Organization == role.Organization) {
			return nil
		}
	}
	user.Roles = append(user.Roles, role)
	user.Revise()
	return nil
}

// VerifyPassword verifies provided password matches to the one in the database.
func (user *User) VerifyPassword(s string) error {
	if len(user.Passwords) == 0 {
		return errors.ErrUserPasswordNotFound
	}
	for _, p := range user.Passwords {
		if p.Disabled || p.Expired {
			continue
		}
		if p.Match(s) {
			return nil
		}
	}
	return errors.ErrUserPasswordInvalid
}

// VerifyWebAuthnRequest authenticated WebAuthn requests.
func (user *User) VerifyWebAuthnRequest(r *requests.Request) error {
	req, err := unpackWebAuthnRequest(r.WebAuthn.Request)
	if err != nil {
		return err
	}
	for _, token := range user.MfaTokens {
		if token.Disabled {
			continue
		}
		if token.Type != "u2f" {
			continue
		}
		if _, exists := token.Parameters["u2f_id"]; !exists {
			continue
		}
		if req.ID != token.Parameters["u2f_id"] {
			continue
		}
		resp, err := token.WebAuthnRequest(r.WebAuthn.Request)
		if err != nil {
			return errors.ErrWebAuthnVerifyRequest
		}
		if resp == nil {
			return errors.ErrWebAuthnVerifyRequest
		}
		if resp.ClientData.Challenge != r.WebAuthn.Challenge {
			return errors.ErrWebAuthnVerifyRequest
		}
		return nil
	}
	return errors.ErrWebAuthnVerifyRequest
}

// GetMailClaim returns primary email address.
func (user *User) GetMailClaim() string {
	if len(user.EmailAddresses) == 0 {
		return ""
	}
	for _, mail := range user.EmailAddresses {
		if mail.Primary() {
			return mail.Address
		}
	}
	return user.EmailAddresses[0].Address
}

// GetNameClaim returns name field of a claim.
func (user *User) GetNameClaim() string {
	if user.Name == nil {
		return ""
	}
	if name := user.Name.GetNameClaim(); name != "" {
		return name
	}
	return ""
}

// GetRolesClaim returns name field of a claim.
func (user *User) GetRolesClaim() []string {
	var roles []string
	if len(user.Roles) == 0 {
		return roles
	}
	for _, role := range user.Roles {
		roles = append(roles, role.String())
	}
	return roles
}

// GetFullName returns the primary full name for a user.
func (user *User) GetFullName() string {
	if user.Name == nil {
		return ""
	}
	return user.Name.GetFullName()
}

// AddName adds Name for a user identity.
func (user *User) AddName(name *Name) error {
	if len(user.Names) == 0 {
		user.Name = name
		user.Names = append(user.Names, name)
		return nil
	}
	for _, n := range user.Names {
		if name.GetFullName() == n.GetFullName() {
			return nil
		}
	}
	user.Names = append(user.Names, name)
	user.Revise()
	return nil
}

// AddPublicKey adds public key, e.g. GPG or SSH, to a user identity.
func (user *User) AddPublicKey(r *requests.Request) error {
	key, err := NewPublicKey(r)
	if err != nil {
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, err)
	}
	for _, k := range user.PublicKeys {
		if k.Type != key.Type {
			continue
		}
		if k.Fingerprint != key.Fingerprint {
			continue
		}
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, "already exists")
	}
	user.PublicKeys = append(user.PublicKeys, key)
	user.Revise()
	return nil
}

// DeletePublicKey deletes a public key associated with a user.
func (user *User) DeletePublicKey(r *requests.Request) error {
	var found bool
	keys := []*PublicKey{}
	for _, k := range user.PublicKeys {
		if k.ID == r.Key.ID {
			found = true
			continue
		}
		keys = append(keys, k)
	}
	if !found {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.ID, "not found")
	}
	user.PublicKeys = keys
	user.Revise()
	return nil
}

// AddAPIKey adds API key to a user identity.
func (user *User) AddAPIKey(r *requests.Request) error {
	key, err := NewAPIKey(r)
	if err != nil {
		return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)
	}
	user.APIKeys = append(user.APIKeys, key)
	user.Revise()
	return nil
}

// DeleteAPIKey deletes an API key associated with a user.
func (user *User) DeleteAPIKey(r *requests.Request) error {
	var found bool
	keys := []*APIKey{}
	for _, k := range user.APIKeys {
		if k.ID == r.Key.ID {
			found = true
			r.Key.Prefix = k.Prefix
			continue
		}
		keys = append(keys, k)
	}
	if !found {
		return errors.ErrDeleteAPIKey.WithArgs(r.Key.ID, "not found")
	}
	user.APIKeys = keys
	user.Revise()
	return nil
}

// LookupAPIKey performs the lookup of API key.
func (user *User) LookupAPIKey(r *requests.Request) error {
	for _, k := range user.APIKeys {
		if k.Prefix == r.Key.Prefix {
			if k.Match(r.Key.Payload) {
				return nil
			}
			return errors.ErrLookupAPIKeyFailed
		}
	}
	return errors.ErrLookupAPIKeyFailed
}

// AddMfaToken adds MFA token to a user identity.
func (user *User) AddMfaToken(r *requests.Request) error {
	token, err := NewMfaToken(r)
	if err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	for _, k := range user.MfaTokens {
		if k.Secret == token.Secret {
			return errors.ErrAddMfaToken.WithArgs(errors.ErrDuplicateMfaTokenSecret)
		}
		if k.Comment == token.Comment {
			return errors.ErrAddMfaToken.WithArgs(errors.ErrDuplicateMfaTokenComment)
		}
	}
	user.MfaTokens = append(user.MfaTokens, token)
	user.Revise()
	return nil
}

// DeleteMfaToken deletes MFA token associated with a user.
func (user *User) DeleteMfaToken(r *requests.Request) error {
	var found bool
	tokens := []*MfaToken{}
	for _, k := range user.MfaTokens {
		if k.ID == r.MfaToken.ID {
			found = true
			continue
		}
		tokens = append(tokens, k)
	}
	if !found {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, "not found")
	}
	user.MfaTokens = tokens
	user.Revise()
	return nil
}

// GetFlags populates request context with metadata about a user.
func (user *User) GetFlags(r *requests.Request) {
	for _, token := range user.MfaTokens {
		if token.Disabled {
			continue
		}
		r.Flags.MfaConfigured = true
		switch token.Type {
		case "totp":
			r.Flags.MfaApp = true
		case "u2f":
			r.Flags.MfaUniversal = true
		}
	}
}

// ChangePassword changes user password.
func (user *User) ChangePassword(r *requests.Request, keepVersions int) error {
	if err := user.VerifyPassword(r.User.OldPassword); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := user.AddPassword(r.User.Password, keepVersions); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	return nil
}

// UpdatePassword update user password.
func (user *User) UpdatePassword(r *requests.Request, keepVersions int) error {
	if !strings.HasPrefix(r.User.Password, "bcrypt:") {
		// Check whether the existing password matches the newly provided password,
		// and skip updating if it is.
		if user.VerifyPassword(r.User.Password) == nil {
			return nil
		}
	}
	if err := user.AddPassword(r.User.Password, keepVersions); err != nil {
		return errors.ErrUpdateUserPassword.WithArgs(err)
	}
	return nil
}

// GetMetadata returns user metadata.
func (user *User) GetMetadata() *UserMetadata {
	m := &UserMetadata{
		ID:           user.ID,
		Enabled:      user.Enabled,
		Username:     user.Username,
		Title:        user.Title,
		Created:      user.Created,
		LastModified: user.LastModified,
		Revision:     user.Revision,
	}
	if user.Avatar != nil {
		m.Avatar = user.Avatar.Path
	}
	if user.EmailAddress != nil {
		m.Email = user.EmailAddress.ToString()
	}
	if user.Name != nil {
		m.Name = user.Name.ToString()
	}
	return m
}

// GetChallenges returns a list of challenges that should be
// satisfied prior to successfully authenticating a user.
func (user *User) GetChallenges() []string {
	var challenges []string
	challenges = append(challenges, "password")
	if len(user.MfaTokens) > 0 {
		challenges = append(challenges, "mfa")
	}
	return challenges
}

// Revise increments revision number and last modified timestamp.
func (user *User) Revise() {
	user.Revision++
	user.LastModified = time.Now().UTC()
}

// HasAdminRights returns true if the user has admin rights.
func (user *User) HasAdminRights() bool {
	for _, role := range user.Roles {
		if role.Name == "admin" && role.Organization == "authp" {
			return true
		}
	}
	return false
}
