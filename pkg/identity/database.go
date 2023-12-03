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
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/utils"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"github.com/greenpau/versioned"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	app           *versioned.PackageManager
	appVersion    string
	gitBranch     string
	gitCommit     string
	buildUser     string
	buildDate     string
	defaultPolicy = Policy{
		User: UserPolicy{
			MinLength:            3,
			MaxLength:            50,
			AllowNonAlphaNumeric: false,
			AllowUppercase:       false,
		},
		Password: PasswordPolicy{
			KeepVersions:           10,
			MinLength:              8,
			MaxLength:              128,
			RequireUppercase:       false,
			RequireLowercase:       false,
			RequireNumber:          false,
			RequireNonAlphaNumeric: false,
			BlockReuse:             false,
			BlockPasswordChange:    false,
		},
	}
)

func init() {
	app = versioned.NewPackageManager("authdb")
	app.Description = "authdb"
	app.Documentation = "https://github.com/greenpau/go-authcrunch"
	app.SetVersion(appVersion, "1.0.46")
	app.SetGitBranch(gitBranch, "main")
	app.SetGitCommit(gitCommit, "v1.0.45-1-g04ef714")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

// Policy represents database usage policy.
type Policy struct {
	Password PasswordPolicy `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	User     UserPolicy     `json:"user,omitempty" xml:"user,omitempty" yaml:"user,omitempty"`
}

// PasswordPolicy represents database password policy.
type PasswordPolicy struct {
	KeepVersions           int  `json:"keep_versions" xml:"keep_versions" yaml:"keep_versions"`
	MinLength              int  `json:"min_length" xml:"min_length" yaml:"min_length"`
	MaxLength              int  `json:"max_length" xml:"max_length" yaml:"max_length"`
	RequireUppercase       bool `json:"require_uppercase" xml:"require_uppercase" yaml:"require_uppercase"`
	RequireLowercase       bool `json:"require_lowercase" xml:"require_lowercase" yaml:"require_lowercase"`
	RequireNumber          bool `json:"require_number" xml:"require_number" yaml:"require_number"`
	RequireNonAlphaNumeric bool `json:"require_non_alpha_numeric" xml:"require_non_alpha_numeric" yaml:"require_non_alpha_numeric"`
	BlockReuse             bool `json:"block_reuse" xml:"block_reuse" yaml:"block_reuse"`
	BlockPasswordChange    bool `json:"block_password_change" xml:"block_password_change" yaml:"block_password_change"`
}

// UserPolicy represents database username policy
type UserPolicy struct {
	MinLength            int  `json:"min_length" xml:"min_length" yaml:"min_length"`
	MaxLength            int  `json:"max_length" xml:"max_length" yaml:"max_length"`
	AllowNonAlphaNumeric bool `json:"allow_non_alpha_numeric" xml:"allow_non_alpha_numeric" yaml:"allow_non_alpha_numeric"`
	AllowUppercase       bool `json:"allow_uppercase" xml:"allow_uppercase" yaml:"allow_uppercase"`
}

// Database is user identity database.
type Database struct {
	mu              *sync.RWMutex
	Version         string    `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Policy          Policy    `json:"policy,omitempty" xml:"policy,omitempty" yaml:"policy,omitempty"`
	Revision        uint64    `json:"revision,omitempty" xml:"revision,omitempty" yaml:"revision,omitempty"`
	LastModified    time.Time `json:"last_modified,omitempty" xml:"last_modified,omitempty" yaml:"last_modified,omitempty"`
	Users           []*User   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
	refEmailAddress map[string]*User
	refUsername     map[string]*User
	refID           map[string]*User
	refAPIKey       map[string]*User
	path            string
}

// NewDatabase return an instance of Database.
func NewDatabase(fp string) (*Database, error) {
	if fp == "/dev/null" {
		return nil, errors.ErrNewDatabase.WithArgs(fp, "null path")
	}

	db := &Database{
		mu:              &sync.RWMutex{},
		path:            fp,
		refUsername:     make(map[string]*User),
		refID:           make(map[string]*User),
		refEmailAddress: make(map[string]*User),
		refAPIKey:       make(map[string]*User),
	}
	fileInfo, err := os.Stat(fp)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		if err := os.MkdirAll(filepath.Dir(fp), 0700); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		db.Version = app.Version
		db.enforceDefaultPolicy()
		if err := db.commit(); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
	} else {
		if fileInfo.IsDir() {
			return nil, errors.ErrNewDatabase.WithArgs(fp, "path points to a directory")
		}
		b, err := utils.ReadFileBytes(fp)
		if err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		if err := json.Unmarshal(b, db); err != nil {
			return nil, errors.ErrNewDatabase.WithArgs(fp, err)
		}
		if changed := db.enforceDefaultPolicy(); changed {
			if err := db.commit(); err != nil {
				return nil, errors.ErrNewDatabase.WithArgs(fp, err)
			}
		}
	}

	// db.mu = &sync.RWMutex{}
	// db.path = fp
	db.Version = app.Version

	for _, user := range db.Users {
		if err := user.Valid(); err != nil {
			return nil, errors.ErrNewDatabaseInvalidUser.WithArgs(user, err)
		}
		username := strings.ToLower(user.Username)
		if _, exists := db.refUsername[username]; exists {
			return nil, errors.ErrNewDatabaseDuplicateUser.WithArgs(user.Username, user)
		}
		if _, exists := db.refID[user.ID]; exists {
			return nil, errors.ErrNewDatabaseDuplicateUserID.WithArgs(user.ID, user)
		}
		db.refUsername[username] = user
		db.refID[user.ID] = user
		for _, email := range user.EmailAddresses {
			emailAddress := strings.ToLower(email.Address)
			if _, exists := db.refEmailAddress[emailAddress]; exists {
				return nil, errors.ErrNewDatabaseDuplicateEmail.WithArgs(emailAddress, user)
			}
			db.refEmailAddress[emailAddress] = user
		}
		for _, p := range user.Passwords {
			if p.Algorithm == "" {
				p.Algorithm = "bcrypt"
			}
		}
		for _, apiKey := range user.APIKeys {
			if _, exists := db.refAPIKey[apiKey.Prefix]; exists {
				return nil, errors.ErrNewDatabaseDuplicateAPIKey.WithArgs(apiKey.Prefix, user)
			}
			db.refAPIKey[apiKey.Prefix] = user
		}
	}
	return db, nil
}

func (db *Database) enforceDefaultPolicy() bool {
	var changes int
	if db.Policy.Password.MinLength == 0 {
		db.Policy.Password.MinLength = defaultPolicy.Password.MinLength
		changes++
	}
	if db.Policy.Password.MaxLength == 0 {
		db.Policy.Password.MaxLength = defaultPolicy.Password.MaxLength
		changes++
	}
	if db.Policy.Password.KeepVersions == 0 {
		db.Policy.Password.KeepVersions = defaultPolicy.Password.KeepVersions
		changes++
	}
	if db.Policy.User.MinLength == 0 {
		db.Policy.User.MinLength = defaultPolicy.User.MinLength
		changes++
	}
	if db.Policy.User.MaxLength == 0 {
		db.Policy.User.MaxLength = defaultPolicy.User.MaxLength
		changes++
	}
	if changes > 0 {
		return true
	}
	return false
}

func (db *Database) checkPolicyCompliance(username, password string) error {
	if err := db.checkUserPolicyCompliance(username); err != nil {
		return err
	}
	if err := db.checkPasswordPolicyCompliance(password); err != nil {
		return err
	}
	return nil
}

func (db *Database) checkUserPolicyCompliance(s string) error {
	if len(s) > db.Policy.User.MaxLength || len(s) < db.Policy.User.MinLength {
		return errors.ErrUserPolicyCompliance
	}
	return nil
}

func (db *Database) checkPasswordPolicyCompliance(s string) error {
	if len(s) > db.Policy.Password.MaxLength || len(s) < db.Policy.Password.MinLength {
		return errors.ErrPasswordPolicyCompliance
	}
	return nil
}

// GetPath returns the path  to Database.
func (db *Database) GetPath() string {
	return db.path
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if err := db.checkPolicyCompliance(r.User.Username, r.User.Password); err != nil {
		return errors.ErrAddUser.WithArgs(r.User.Username, err)
	}

	user, err := NewUserWithRoles(
		r.User.Username, r.User.Password,
		r.User.Email, r.User.FullName,
		r.User.Roles,
	)
	if err != nil {
		return errors.ErrAddUser.WithArgs(r.User.Username, err)
	}
	for i := 0; i < 10; i++ {
		id := NewID()
		if _, exists := db.refID[id]; !exists {
			user.ID = id
			break
		}
	}
	username := strings.ToLower(user.Username)
	if _, exists := db.refUsername[username]; exists {
		return errors.ErrAddUser.WithArgs(username, "username already in use")
	}

	emailAddresses := []string{}
	for _, email := range user.EmailAddresses {
		emailAddress := strings.ToLower(email.Address)
		if _, exists := db.refEmailAddress[emailAddress]; exists {
			return errors.ErrAddUser.WithArgs(emailAddress, "email address already in use")
		}
		emailAddresses = append(emailAddresses, emailAddress)
	}

	if r.Query.ID != "" {
		// Handle the case where registration ID is being provided with the request.
		user.Registration = NewRegistration(r.Query.ID)
	}

	db.refUsername[username] = user
	db.refID[user.ID] = user
	for _, emailAddress := range emailAddresses {
		db.refEmailAddress[emailAddress] = user
	}
	db.Users = append(db.Users, user)

	if err := db.commit(); err != nil {
		return errors.ErrAddUser.WithArgs(username, err)
	}
	return nil
}

// GetUsers return a list of user identities.
func (db *Database) GetUsers(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	_, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetUsers.WithArgs(err)
	}
	bundle := NewUserMetadataBundle()
	for _, user := range db.Users {
		bundle.Add(user.GetMetadata())
	}
	r.Response.Payload = bundle
	return nil
}

// GetUser return an instance of User.
func (db *Database) GetUser(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetUsers.WithArgs(err)
	}
	r.Response.Payload = user
	return nil
}

// DeleteUser deletes a user by user id.
func (db *Database) DeleteUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	// user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	_, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeleteUser.WithArgs(r.Query.ID, err)
	}
	return errors.ErrDeleteUser.WithArgs(r.Query.ID, "user delete operation is not supported")
	// TODO: how do we delete a user ???

	// if err := user.DeletePublicKey(r); err != nil {
	//	return err
	//}
	/*
		if err := db.commit(); err != nil {
			return errors.ErrDeleteUser.WithArgs(r.Query.ID, err)
		}
		return nil
	*/
}

// AuthenticateUser adds user identity to the database.
func (db *Database) AuthenticateUser(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.getUser(r.User.Username)
	if err != nil {
		r.Response.Code = 400
		// Calculate password hash as the means to prevent user discovery.
		NewPassword(r.User.Password)
		return errors.ErrAuthFailed.WithArgs(err)
	}

	switch {
	case r.User.Password != "":
		if err := user.VerifyPassword(r.User.Password); err != nil {
			r.Response.Code = 400
			return errors.ErrAuthFailed.WithArgs(err)
		}
	case r.WebAuthn.Request != "":
		if err := user.VerifyWebAuthnRequest(r); err != nil {
			r.Response.Code = 400
			return errors.ErrAuthFailed.WithArgs(err)
		}
	default:
		r.Response.Code = 400
		return errors.ErrAuthFailed.WithArgs("malformed auth request")
	}

	r.Response.Code = 200
	return nil
}

// getUser return User by either email address or username.
func (db *Database) getUser(s string) (*User, error) {
	if strings.Contains(s, "@") {
		return db.getUserByEmailAddress(s)
	}
	return db.getUserByUsername(s)
}

// getUserByID returns a user by id
func (db *Database) getUserByID(s string) (*User, error) {
	s = strings.ToLower(s)
	user, exists := db.refID[s]
	if exists && user != nil {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// getUserByUsername returns a user by username
func (db *Database) getUserByUsername(s string) (*User, error) {
	if len(s) < 2 {
		return nil, errors.ErrDatabaseUserNotFound
	}
	s = strings.ToLower(s)
	user, exists := db.refUsername[s]
	if exists && user != nil {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// getUserByEmailAddress returns a liast of users associated with a specific email
// address.
func (db *Database) getUserByEmailAddress(s string) (*User, error) {
	if len(s) < 6 {
		return nil, errors.ErrDatabaseUserNotFound
	}
	s = strings.ToLower(s)
	user, exists := db.refEmailAddress[s]
	if exists && user != nil {
		return user, nil
	}
	return nil, errors.ErrDatabaseUserNotFound
}

// GetUserCount returns user count.
func (db *Database) GetUserCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.Users)
}

// GetAdminUserCount returns user count.
func (db *Database) GetAdminUserCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var counter int
	for _, user := range db.Users {
		if user.HasAdminRights() {
			counter++
		}
	}
	return counter
}

// Save saves the database.
func (db *Database) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.commit()
}

// Copy copies the database to another file.
func (db *Database) Copy(fp string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	path := db.path
	db.path = fp
	err := db.commit()
	db.path = path
	return err
}

// commit writes the database contents to a file.
func (db *Database) commit() error {
	db.Revision++
	db.LastModified = time.Now().UTC()
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if err := ioutil.WriteFile(db.path, []byte(data), 0600); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	return nil
}

func (db *Database) validateUserIdentity(username, email string) (*User, error) {
	user1, err := db.getUserByUsername(username)
	if err != nil {
		return nil, err
	}
	user2, err := db.getUserByEmailAddress(email)
	if err != nil {
		return nil, err
	}
	if user1.ID != user2.ID {
		return nil, errors.ErrDatabaseInvalidUser
	}
	return user1, nil
}

// AddPublicKey adds public key, e.g. GPG or SSH, for a user.
func (db *Database) AddPublicKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, err)
	}
	if err := user.AddPublicKey(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrAddPublicKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// GetPublicKeys returns a list of public keys associated with a user.
func (db *Database) GetPublicKeys(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetPublicKeys.WithArgs(r.Key.Usage, err)
	}
	bundle := NewPublicKeyBundle()
	for _, k := range user.PublicKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		if k.Disabled {
			continue
		}
		bundle.Add(k)
	}
	r.Response.Payload = bundle
	return nil
}

// DeletePublicKey deletes a public key associated with a user by key id.
func (db *Database) DeletePublicKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.ID, err)
	}
	if err := user.DeletePublicKey(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrDeletePublicKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// AddAPIKey adds API key for a user.
func (db *Database) AddAPIKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)
	}
	s := util.GetRandomString(72)
	failCount := 0
	for {
		hk, err := NewPassword(s)
		if err != nil {
			if failCount > 10 {
				return err
			}
			failCount++
			continue
		}
		keyPrefix := string(s[:24])
		if _, exists := db.refAPIKey[keyPrefix]; exists {
			continue
		}
		r.Response.Payload = s
		r.Key.Payload = hk.Hash
		r.Key.Prefix = keyPrefix
		if err := user.AddAPIKey(r); err != nil {
			return err
		}
		db.refAPIKey[keyPrefix] = user
		break
	}

	if err := db.commit(); err != nil {
		return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// DeleteAPIKey deletes an API key associated with a user by key id.
func (db *Database) DeleteAPIKey(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeleteAPIKey.WithArgs(r.Key.ID, err)
	}
	if err := user.DeleteAPIKey(r); err != nil {
		return err
	}
	delete(db.refAPIKey, r.Key.Prefix)
	if err := db.commit(); err != nil {
		return errors.ErrDeleteAPIKey.WithArgs(r.Key.Usage, err)
	}
	return nil
}

// GetAPIKeys returns a list of API keys associated with a user.
func (db *Database) GetAPIKeys(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetAPIKeys.WithArgs(r.Key.Usage, err)
	}
	bundle := NewAPIKeyBundle()
	for _, k := range user.APIKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		if k.Disabled {
			continue
		}
		bundle.Add(k)
	}
	r.Response.Payload = bundle
	return nil
}

// ChangeUserPassword change user password.
func (db *Database) ChangeUserPassword(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := db.checkPasswordPolicyCompliance(r.User.Password); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	if err := user.ChangePassword(r, db.Policy.Password.KeepVersions); err != nil {
		return err
	}
	// if db.Policy.Password.KeepVersions
	if err := db.commit(); err != nil {
		return errors.ErrChangeUserPassword.WithArgs(err)
	}
	return nil
}

// UpdateUserPassword change user password.
func (db *Database) UpdateUserPassword(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUserPassword.WithArgs(err)
	}
	if err := db.checkPasswordPolicyCompliance(r.User.Password); err != nil {
		return errors.ErrUpdateUserPassword.WithArgs(err)
	}
	if err := user.UpdatePassword(r, db.Policy.Password.KeepVersions); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUserPassword.WithArgs(err)
	}
	return nil
}

// IdentifyUser returns user identity and a list of challenges that should be
// satisfied prior to successfully authenticating a user.
func (db *Database) IdentifyUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.getUser(r.User.Username)
	if err != nil {
		r.User.Username = "nobody"
		r.User.Email = "nobody@localhost"
		r.User.Challenges = []string{"password"}
		return nil
	}
	if r.Flags.Enabled {
		user.GetFlags(r)
	}
	r.User.Username = user.Username
	r.User.Email = user.GetMailClaim()
	r.User.FullName = user.GetNameClaim()
	r.User.Roles = user.GetRolesClaim()
	r.User.Challenges = user.GetChallenges()
	r.Response.Code = 200
	return nil
}

// LookupAPIKey returns username and email associated with the provided API
// key.
func (db *Database) LookupAPIKey(r *requests.Request) error {
	if r.Key.Payload == "" {
		return errors.ErrLookupAPIKeyPayloadEmpty
	}
	if len(r.Key.Payload) < 72 {
		return errors.ErrLookupAPIKeyMalformedPayload
	}
	r.Key.Prefix = string(r.Key.Payload[:24])
	db.mu.Lock()
	defer db.mu.Unlock()
	user, exists := db.refAPIKey[r.Key.Prefix]
	if !exists {
		return errors.ErrLookupAPIKeyFailed
	}
	if err := user.LookupAPIKey(r); err != nil {
		return err
	}
	r.User.Username = user.Username
	r.User.Email = user.GetMailClaim()
	r.Response.Code = 200
	return nil
}

// AddMfaToken adds MFA token for a user.
func (db *Database) AddMfaToken(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	if err := user.AddMfaToken(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	return nil
}

// GetMfaTokens returns a list of MFA tokens associated with a user.
func (db *Database) GetMfaTokens(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetMfaTokens.WithArgs(err)
	}
	bundle := NewMfaTokenBundle()
	for _, token := range user.MfaTokens {
		if token.Disabled {
			continue
		}
		bundle.Add(token)
	}
	r.Response.Payload = bundle
	return nil
}

// DeleteMfaToken deletes MFA token associated with a user by token id.
func (db *Database) DeleteMfaToken(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, err)
	}
	if err := user.DeleteMfaToken(r); err != nil {
		return err
	}
	if err := db.commit(); err != nil {
		return errors.ErrDeleteMfaToken.WithArgs(r.MfaToken.ID, err)
	}
	return nil
}

// GetUsernamePolicySummary returns the summary of username policy.
func (db *Database) GetUsernamePolicySummary() string {
	var sb strings.Builder
	var charRestrictions []string
	sb.WriteString("A username should be")
	sb.WriteString(fmt.Sprintf(" %d-%d character long string", db.Policy.User.MinLength, db.Policy.User.MaxLength))
	if !db.Policy.User.AllowUppercase {
		charRestrictions = append(charRestrictions, "lowercase")
	}
	if !db.Policy.User.AllowNonAlphaNumeric {
		charRestrictions = append(charRestrictions, "alpha-numeric")
	}
	if len(charRestrictions) > 0 {
		sb.WriteString(fmt.Sprintf(" with %s characters", strings.Join(charRestrictions, ", ")))
	}
	return sb.String()
}

// GetUsernamePolicyRegex returns regex for usernames.
func (db *Database) GetUsernamePolicyRegex() string {
	var startChars, allowedChars string
	if !db.Policy.User.AllowUppercase {
		startChars = "a-z"
		allowedChars = "a-z0-9"
	} else {
		startChars = "a-zA-Z"
		allowedChars = "a-zA-Z0-9"
	}
	if db.Policy.User.AllowNonAlphaNumeric {
		allowedChars += "-_."
	}
	return fmt.Sprintf("^[%s][%s]{%d,%d}$", startChars, allowedChars, db.Policy.User.MinLength-1, db.Policy.User.MaxLength-1)
}

// GetPasswordPolicySummary returns the summary of password policy.
func (db *Database) GetPasswordPolicySummary() string {
	var sb strings.Builder
	var charRestrictions []string
	sb.WriteString("A password should be")
	sb.WriteString(fmt.Sprintf(" %d-%d character long string", db.Policy.Password.MinLength, db.Policy.Password.MaxLength))
	if db.Policy.Password.RequireUppercase {
		charRestrictions = append(charRestrictions, "uppercase")
	}
	if db.Policy.Password.RequireLowercase {
		charRestrictions = append(charRestrictions, "lowercase")
	}
	if db.Policy.Password.RequireNumber {
		charRestrictions = append(charRestrictions, "numbers")
	}
	if db.Policy.Password.RequireNonAlphaNumeric {
		charRestrictions = append(charRestrictions, "non alpha-numeric")
	}

	if len(charRestrictions) > 0 {
		sb.WriteString(fmt.Sprintf(" with %s characters", strings.Join(charRestrictions, ", ")))
	}
	return sb.String()
}

// GetPasswordPolicyRegex returns regex for passwords.
func (db *Database) GetPasswordPolicyRegex() string {
	var allowedChars string
	if db.Policy.Password.RequireUppercase {
		allowedChars += "(?=.*[A-Z])"
	}
	if db.Policy.Password.RequireLowercase {
		allowedChars += "(?=.*[a-z].*[a-z])"
	}
	if db.Policy.Password.RequireNumber {
		allowedChars += "(?=.*[0-9].*[0-9])"
	}
	if db.Policy.Password.RequireNonAlphaNumeric {
		allowedChars += "(?=.*[~!@#$&*])"
	}

	return fmt.Sprintf("^%s.{%d,%d}$", allowedChars, db.Policy.Password.MinLength, db.Policy.Password.MaxLength)

}

// UserExists checks whether user exists.
func (db *Database) UserExists(username, emailAddress string) (bool, error) {
	username = strings.ToLower(username)
	emailAddress = strings.ToLower(emailAddress)
	user1, _ := db.refUsername[username]
	user2, _ := db.refEmailAddress[emailAddress]
	switch {
	case user1 == nil && user2 == nil:
		return false, nil
	case user1 == nil:
		return false, fmt.Errorf("email is registered to a user, while username not found")
	case user2 == nil:
		return false, fmt.Errorf("username is registered to a user, while email not found")
	}
	if user1.ID != user2.ID {
		return false, fmt.Errorf("username and email address belong to two different users")
	}
	return true, nil
}
