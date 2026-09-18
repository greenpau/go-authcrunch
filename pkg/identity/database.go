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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	"github.com/greenpau/versioned"
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

var apiKeyRegexPattern = regexp.MustCompile(`^[A-Za-z0-9]{64,72}$`)

func init() {
	app = versioned.NewPackageManager("authdb")
	app.Description = "authdb"
	app.Documentation = "https://github.com/greenpau/go-authcrunch"
	app.SetVersion(appVersion, "1.2.6")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

// GetVersion returns database version.
func GetVersion() string {
	return app.Banner()
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
	LoadedAt        time.Time `json:"loaded_at,omitempty" xml:"loaded_at,omitempty" yaml:"loaded_at,omitempty"`
	Users           []*User   `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`
	refEmailAddress map[string]*User
	refUsername     map[string]*User
	refID           map[string]*User
	refAPIKey       map[string]*User
	path            string
	inMemory        bool
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
		inMemory:        fp == ":memory:",
	}
	fileInfo, err := os.Stat(fp)
	if err != nil {
		if !db.inMemory {
			if !os.IsNotExist(err) {
				return nil, errors.ErrNewDatabase.WithArgs(fp, err)
			}
			if err := os.MkdirAll(filepath.Dir(fp), 0700); err != nil {
				return nil, errors.ErrNewDatabase.WithArgs(fp, err)
			}
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
		b, err := fileutil.ReadFileBytes(fp)
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
	db.LoadedAt = time.Now().UTC()
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

// CheckPolicyCompliance performs policy compliance for username and password.
func (db *Database) CheckPolicyCompliance(username, password string) error {
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
		return errors.ErrPasswordPolicyCompliance.WithArgs(fmt.Errorf("password length is %d characters", len(s)))
	}
	return nil
}

// GetPath returns the path  to Database.
func (db *Database) GetPath() string {
	return db.path
}

// ResetUserPassword resets user password in database.
func (db *Database) ResetUserPassword(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.CheckPolicyCompliance(r.User.Username, r.User.Password); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	for _, u := range db.Users {
		if u.ID == user.ID {
			if err := user.ResetPassword(r.User.Password, db.Policy.Password.KeepVersions); err != nil {
				return errors.ErrUpdateUser.WithArgs(err)
			}
			break
		}
	}

	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}
	return nil

}

// OverwriteUserRoles overwrites user roles in Database.
func (db *Database) OverwriteUserRoles(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	roles := []string{}

	for _, u := range db.Users {
		if u.ID == user.ID {
			if err := u.OverwriteRoles(r.User.Roles); err != nil {
				return errors.ErrUpdateUser.WithArgs(err)
			}
			roles = u.GetRolesClaim()
			break
		}
	}

	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	r.Response.Payload = roles
	return nil
}

// AddUserRoles overwrites user roles in Database.
func (db *Database) AddUserRoles(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	roles := []string{}

	for _, u := range db.Users {
		if u.ID == user.ID {
			if err := u.AddRoles(r.User.Roles); err != nil {
				return errors.ErrUpdateUser.WithArgs(err)
			}
			roles = u.GetRolesClaim()
			break
		}
	}

	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	r.Response.Payload = roles
	return nil
}

// OverwriteUserAuthChallengeRules overwrites user auth challenge rules in Database.
func (db *Database) OverwriteUserAuthChallengeRules(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	challenges := []string{}

	for _, u := range db.Users {
		if u.ID == user.ID {
			if err := u.OverwriteAuthChallengeRules(r.User.Challenges); err != nil {
				return errors.ErrUpdateUser.WithArgs(err)
			}
			challenges = u.GetAuthChallengeRules()
			break
		}
	}

	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	r.Response.Payload = challenges
	return nil
}

// AddUser adds user identity to the database.
func (db *Database) AddUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if err := db.CheckPolicyCompliance(r.User.Username, r.User.Password); err != nil {
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

// ListUsers return a list of user identities.
func (db *Database) ListUsers() []map[string]any {
	db.mu.RLock()
	defer db.mu.RUnlock()
	users := []map[string]any{}
	for _, user := range db.Users {
		data := user.GetMetadata()
		if data == nil {
			continue
		}
		dataMap := data.AsMap()
		if dataMap == nil {
			continue
		}
		roles := []string{}
		for _, role := range user.Roles {
			roles = append(roles, role.String())
		}
		dataMap["roles"] = roles
		dataMap["disabled"] = user.Disabled
		users = append(users, dataMap)
	}
	return users
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
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrDeleteUser.WithArgs(r.User.Username, err)
	}

	delete(db.refID, user.ID)
	delete(db.refUsername, strings.ToLower(user.Username))
	for _, email := range user.EmailAddresses {
		delete(db.refEmailAddress, strings.ToLower(email.Address))
	}
	for _, apiKey := range user.APIKeys {
		delete(db.refAPIKey, apiKey.Prefix)
	}
	for i, u := range db.Users {
		if u.ID == user.ID {
			// Remove the element by joining the parts before and after the index
			db.Users = append(db.Users[:i], db.Users[i+1:]...)
			break
		}
	}
	if err := db.commit(); err != nil {
		return errors.ErrAddUser.WithArgs(r.User.Username, err)
	}
	return nil
}

// DisableUser disables a user by user id.
func (db *Database) DisableUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}

	delete(db.refID, user.ID)
	delete(db.refUsername, strings.ToLower(user.Username))
	for _, email := range user.EmailAddresses {
		delete(db.refEmailAddress, strings.ToLower(email.Address))
	}
	for _, apiKey := range user.APIKeys {
		delete(db.refAPIKey, apiKey.Prefix)
	}
	for _, u := range db.Users {
		if u.ID == user.ID {
			u.Disabled = true
			break
		}
	}
	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}
	return nil
}

// EnableUser disables a user by user id.
func (db *Database) EnableUser(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	var user *User

	for _, u := range db.Users {
		if u.Username != r.User.Username {
			continue
		}
		matchedEmail := false
		for _, addr := range u.EmailAddresses {
			if addr.Address != r.User.Email {
				continue
			}
			matchedEmail = true
			break
		}
		if matchedEmail && u.Disabled {
			user = u
			break
		}
	}

	if user == nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, "no disabled user match")
	}

	username := strings.ToLower(user.Username)

	emailAddresses := []string{}
	for _, email := range user.EmailAddresses {
		emailAddress := strings.ToLower(email.Address)
		emailAddresses = append(emailAddresses, emailAddress)
	}

	db.refUsername[username] = user
	db.refID[user.ID] = user
	for _, emailAddress := range emailAddresses {
		db.refEmailAddress[emailAddress] = user
	}
	for _, apiKey := range user.APIKeys {
		db.refAPIKey[apiKey.Prefix] = user
	}

	for _, u := range db.Users {
		if u.ID == user.ID {
			u.Disabled = false
			break
		}
	}

	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUser.WithArgs(r.User.Username, err)
	}
	return nil
}

// AuthenticateUser adds user identity to the database.
func (db *Database) AuthenticateUser(r *requests.Request) error {
	proof := r.Authentication
	r.Authentication = requests.AuthenticationEvidence{}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.inMemory {
		return db.authenticateUserUnlocked(r, proof)
	}
	var result error
	err := withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return err
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return err
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return err
		}
		if target.Revision != db.Revision {
			db.LoadedAt = time.Now().UTC()
		}
		target.LoadedAt = db.LoadedAt
		result = target.authenticateUserUnlocked(r, proof)
		db.adoptMfaMutationSnapshot(target)
		return nil
	})
	if err != nil {
		r.Response.Code = 500
		return errors.ErrAuthFailed.WithArgs("identity store unavailable")
	}
	return result
}

func (db *Database) authenticateUserUnlocked(r *requests.Request, proof requests.AuthenticationEvidence) error {
	user, err := db.getUser(r.User.Username)
	var passwordErr error
	if r.User.Password != "" {
		// Missing, disabled and existing identities must perform the same
		// bcrypt work, even when stored password costs differ.
		passwordErr = newPasswordVerifier(db.Users).verify(user, r.User.Password)
	}
	if err != nil {
		r.Response.Code = 400
		return errors.ErrAuthFailed.WithArgs(err)
	}

	if user.Disabled {
		r.Response.Code = 401
		return errors.ErrAuthFailed.WithArgs("unauthorized")
	}

	switch {
	case r.User.Password != "":
		if passwordErr != nil {
			r.Response.Code = 400
			return errors.ErrAuthFailed.WithArgs(passwordErr)
		}
	case r.WebAuthn.Request != "":
		if authenticationEvidenceBound(proof) && !db.authenticationEvidenceMatches(proof, user) {
			r.Response.Code = 401
			return errors.ErrAuthFailed.WithArgs("identity changed during authentication")
		}
		if err := user.VerifyWebAuthnRequest(r); err != nil {
			r.Response.Code = 400
			return errors.ErrAuthFailed.WithArgs(err)
		}
	default:
		r.Response.Code = 400
		return errors.ErrAuthFailed.WithArgs("malformed auth request")
	}

	r.Authentication = db.authenticationEvidence(user)
	r.Authentication.AuthenticatedAt = time.Now().Unix()
	if r.User.Password != "" {
		r.Authentication.Method = "pwd"
	} else {
		r.Authentication.Method = "hwk"
	}
	r.Response.Code = 200
	return nil
}

// CheckMfaLockout returns an error if the user is locked out due to
// too many failed MFA attempts.
func (db *Database) CheckMfaLockout(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	locked := false
	err := db.updateMfaFailureStateUnlocked(r, func(user *User) (bool, error) {
		if user.Lockout == nil || user.MfaFailedAttempts == 0 {
			return false, nil
		}
		if user.Lockout.IsLocked() {
			locked = true
			return false, nil
		}
		// Lockout expired, auto-clear.
		user.Lockout.Enabled = false
		user.MfaFailedAttempts = 0
		return true, nil
	})
	if err != nil {
		return errors.ErrMfaLockout.WithArgs("failed reading lockout state")
	}
	if locked {
		return errors.ErrMfaLockout.WithArgs("too many failed attempts")
	}
	return nil
}

// IncrementMfaFailedAttempts increments the MFA failed attempt counter
// and triggers a lockout if the threshold is exceeded.
func (db *Database) IncrementMfaFailedAttempts(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.updateMfaFailureStateUnlocked(r, func(user *User) (bool, error) {
		user.MfaFailedAttempts++
		if user.MfaFailedAttempts >= 10 {
			if user.Lockout == nil {
				user.Lockout = NewLockoutState()
			}
			user.Lockout.Lock(15 * time.Minute)
		}
		return true, nil
	})
}

// ResetMfaFailedAttempts resets the MFA failed attempt counter
// and clears any active lockout.
func (db *Database) ResetMfaFailedAttempts(r *requests.Request) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.updateMfaFailureStateUnlocked(r, func(user *User) (bool, error) {
		if user.MfaFailedAttempts == 0 {
			return false, nil
		}
		user.MfaFailedAttempts = 0
		if user.Lockout != nil {
			user.Lockout.Enabled = false
		}
		return true, nil
	})
}

func (db *Database) updateMfaFailureStateUnlocked(r *requests.Request, update func(*User) (bool, error)) error {
	if db.inMemory {
		user, err := db.getUser(r.User.Username)
		if err != nil {
			return nil
		}
		if authenticationEvidenceBound(r.Authentication) && !db.authenticationEvidenceMatches(r.Authentication, user) {
			return ErrIdentityRequestDenied
		}
		changed, resultErr := update(user)
		if changed {
			if err := db.commitUnlocked(); err != nil {
				return err
			}
		}
		return resultErr
	}
	return withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		target.LoadedAt = db.LoadedAt
		user, err := target.getUser(r.User.Username)
		if err != nil {
			db.adoptMfaMutationSnapshot(target)
			return nil
		}
		if authenticationEvidenceBound(r.Authentication) && !target.authenticationEvidenceMatches(r.Authentication, user) {
			db.adoptMfaMutationSnapshot(target)
			return ErrIdentityRequestDenied
		}
		changed, resultErr := update(user)
		if changed {
			if err := target.commitUnlocked(); err != nil {
				return err
			}
		}
		db.adoptMfaMutationSnapshot(target)
		return resultErr
	})
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
	data, err := json.Marshal(db)
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(fp, err)
	}
	target := &Database{path: fp}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(fp, err)
	}
	if err := target.indexMfaMutationSnapshot(); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(fp, err)
	}
	target.LoadedAt = db.LoadedAt
	return withDatabaseFileLock(fp, target.commitUnlocked)
}

// commit writes the database contents to a file.
func (db *Database) commit() error {
	if db.inMemory {
		return db.commitUnlocked()
	}
	return withDatabaseFileLock(db.path, func() error {
		if err := db.mergePersistedTOTPCounters(); err != nil {
			return err
		}
		return db.commitUnlocked()
	})
}

func (db *Database) commitUnlocked() error {
	db.Revision++
	db.LastModified = time.Now().UTC()
	return db.writeSnapshotUnlocked()
}

func (db *Database) writeSnapshotUnlocked() error {
	if db.inMemory {
		return nil
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if err := writeDatabaseFileAtomically(db.path, data); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	return nil
}

func (db *Database) mergePersistedTOTPCounters() error {
	if info, err := os.Stat(db.path); err == nil && info.IsDir() {
		file, openErr := os.OpenFile(db.path, os.O_WRONLY, 0600)
		if file != nil {
			_ = file.Close()
		}
		return errors.ErrDatabaseCommit.WithArgs(db.path, openErr)
	}
	data, err := os.ReadFile(db.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	persisted := &Database{path: db.path}
	if err := json.Unmarshal(data, persisted); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(db.path, err)
	}
	if persisted.Revision != db.Revision {
		if err := persisted.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		db.adoptMfaMutationSnapshot(persisted)
		db.LoadedAt = time.Now().UTC()
		return errors.ErrDatabaseCommit.WithArgs(db.path, "database changed since it was loaded")
	}
	persistedCounters := make(map[string]map[string]uint64)
	for _, user := range persisted.Users {
		if user == nil {
			continue
		}
		for _, token := range user.MfaTokens {
			if token == nil || token.LastTOTPCounter == nil {
				continue
			}
			if persistedCounters[user.ID] == nil {
				persistedCounters[user.ID] = make(map[string]uint64)
			}
			persistedCounters[user.ID][token.ID] = *token.LastTOTPCounter
		}
	}
	for _, user := range db.Users {
		if user == nil {
			continue
		}
		for _, token := range user.MfaTokens {
			if token == nil {
				continue
			}
			counter, exists := persistedCounters[user.ID][token.ID]
			if !exists || (token.LastTOTPCounter != nil && counter <= *token.LastTOTPCounter) {
				continue
			}
			token.LastTOTPCounter = &counter
		}
	}
	return nil
}

func (db *Database) refreshPersistedSnapshotUnlocked() error {
	if db.inMemory {
		return nil
	}
	return withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		if target.Revision == db.Revision {
			return nil
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrDatabaseCommit.WithArgs(db.path, err)
		}
		db.adoptMfaMutationSnapshot(target)
		db.LoadedAt = time.Now().UTC()
		return nil
	})
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
			if !r.Key.IncludeAll {
				continue
			}
		}
		bundle.Add(k)
	}
	r.Response.Payload = bundle
	return nil
}

// GetPublicKey returns a public key associated with a user.
func (db *Database) GetPublicKey(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetPublicKey.WithArgs(r.Key.Usage, err)
	}
	for _, k := range user.PublicKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		if k.Disabled {
			if !r.Key.IncludeAll {
				continue
			}
		}
		if k.ID != r.Key.ID {
			continue
		}
		r.Response.Payload = k
		return nil
	}
	return errors.ErrGetPublicKey.WithArgs(r.Key.Usage, "not found")
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

	s := r.Key.Payload

	if s == "" {
		s = util.GetRandomString(72)
	}

	if !strings.HasPrefix(r.Key.Payload, "bcrypt:") {
		if len(s) < 64 {
			return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, "the key is too short")
		}
		if len(s) > 72 {
			return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, "the key is too long")
		}
		if !apiKeyRegexPattern.MatchString(s) {
			return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, "the key is non compliant")
		}
	}

	if r.Key.Prefix != "" {
		if r.Key.Payload == "" {
			return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, fmt.Errorf("api key payload is empty"))
		}
		if refUser, exists := db.refAPIKey[r.Key.Prefix]; exists {
			if refUser.ID != user.ID {
				return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, fmt.Errorf("api key prefix is mapped to another user"))
			}
		} else {
			var hk *Password
			var err error
			if strings.HasPrefix(r.Key.Payload, "bcrypt:") {
				hk, err = ParseHashedPassword(s)
				if err != nil {
					return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)
				}
			} else {
				failCount := 0
				for {
					hk, err = NewPassword(s)
					if err != nil {
						if failCount > 10 {
							return err
						}
						failCount++
						continue
					}
					break
				}
			}
			r.Response.Payload = s
			r.Key.Payload = hk.Hash
			r.Key.Usage = "api"
			r.Key.Comment = strings.ToUpper(util.GetRandomStringFromRange(8, 14))
			if err := user.AddAPIKey(r); err != nil {
				return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)

			}
			db.refAPIKey[r.Key.Prefix] = user
		}

		if err := db.commit(); err != nil {
			return errors.ErrAddAPIKey.WithArgs(r.Key.Usage, err)
		}
		return nil
	}

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

// GetAPIKey returns an API key associated with a user.
func (db *Database) GetAPIKey(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetAPIKey.WithArgs(r.Key.Usage, err)
	}
	for _, k := range user.APIKeys {
		if k.Usage != r.Key.Usage {
			continue
		}
		if k.Disabled {
			continue
		}
		if k.ID != r.Key.ID {
			continue
		}
		r.Response.Payload = k
		return nil
	}
	return errors.ErrGetAPIKey.WithArgs(r.Key.Usage, "not found")
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
	user.CredentialVersion++
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
	user.CredentialVersion++
	if err := db.commit(); err != nil {
		return errors.ErrUpdateUserPassword.WithArgs(err)
	}
	return nil
}

// IdentifyUser returns user identity and a list of challenges that should be
// satisfied prior to successfully authenticating a user.
func (db *Database) IdentifyUser(r *requests.Request) error {
	r.Authentication = requests.AuthenticationEvidence{}
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := db.refreshPersistedSnapshotUnlocked(); err != nil {
		return err
	}
	user, err := db.getUser(r.User.Username)
	if err != nil {
		r.User.Username = "nobody"
		r.User.Email = "nobody@localhost"
		r.User.Challenges = []string{"password"}
		return nil
	}
	if user.Disabled {
		r.User.Username = "nobody"
		r.User.Email = "nobody@localhost"
		r.User.Challenges = []string{"password"}
		return nil
	}
	if r.Flags.Enabled {
		user.GetFlags(r)
	}
	r.Authentication = db.authenticationEvidence(user)
	r.User.Username = user.Username
	r.User.Email = user.GetMailClaim()
	r.User.FullName = user.GetNameClaim()
	r.User.Roles = user.GetRolesClaim()
	challenges, err := user.GetChallenges()
	if err != nil {
		return err
	}
	r.User.Challenges = challenges
	r.Response.Code = 200
	return nil
}

// LookupAPIKey returns username and email associated with the provided API
// key.
func (db *Database) LookupAPIKey(r *requests.Request) error {
	if r.Key.Payload == "" {
		return errors.ErrLookupAPIKeyPayloadEmpty
	}
	if len(r.Key.Payload) < 64 || len(r.Key.Payload) > 72 {
		return errors.ErrLookupAPIKeyMalformedPayload
	}
	r.Key.Prefix = string(r.Key.Payload[:24])
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.inMemory {
		return db.lookupAPIKeyUnlocked(r)
	}
	var result error
	err := withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return err
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return err
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return err
		}
		if target.Revision != db.Revision {
			db.LoadedAt = time.Now().UTC()
		}
		target.LoadedAt = db.LoadedAt
		result = target.lookupAPIKeyUnlocked(r)
		db.adoptMfaMutationSnapshot(target)
		return nil
	})
	if err != nil {
		return errors.ErrLookupAPIKeyFailed
	}
	return result
}

func (db *Database) lookupAPIKeyUnlocked(r *requests.Request) error {
	user, exists := db.refAPIKey[r.Key.Prefix]
	if !exists || user.Disabled {
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
	return db.mutateMfaToken(r, false)
}

// EnrollMfaToken adds a factor only when no enabled factor exists. Login
// enrollment cannot replace proof of an already-configured factor.
func (db *Database) EnrollMfaToken(r *requests.Request) error {
	return db.mutateMfaToken(r, true)
}

func (db *Database) mutateMfaToken(r *requests.Request, enrollment bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if r == nil {
		return errors.ErrAddMfaToken.WithArgs("request is nil")
	}
	cached, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	bound, err := db.validateMfaTokenMutationEvidence(r.Authentication, cached)
	if err != nil {
		return err
	}
	if enrollment && cached.Disabled {
		return errors.ErrAddMfaToken.WithArgs("identity changed before MFA enrollment")
	}
	if db.inMemory || (!enrollment && !bound) {
		return db.addMfaTokenUnlocked(r, enrollment, db.commit)
	}
	return withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrAddMfaToken.WithArgs(err)
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return errors.ErrAddMfaToken.WithArgs(err)
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrAddMfaToken.WithArgs(err)
		}
		current, err := target.validateUserIdentity(r.User.Username, r.User.Email)
		if err != nil {
			return errors.ErrAddMfaToken.WithArgs(err)
		}
		if current.Disabled {
			return errors.ErrAddMfaToken.WithArgs("identity changed before MFA enrollment")
		}
		if enrollment && (current.ID != cached.ID || current.CredentialVersion != cached.CredentialVersion) {
			return errors.ErrAddMfaToken.WithArgs("identity changed before MFA enrollment")
		}
		if bound {
			if _, err := db.validateMfaTokenMutationEvidence(r.Authentication, current); err != nil {
				return err
			}
		}
		if enrollment {
			for _, token := range current.MfaTokens {
				if token != nil && !token.Disabled {
					return errors.ErrAddMfaToken.WithArgs("an enabled MFA factor already exists")
				}
			}
		}
		// Apply the factor to the fresh persisted snapshot. Committing the live
		// cached snapshot here could overwrite unrelated changes from a realm
		// which shares this database file.
		target.LoadedAt = db.LoadedAt
		return target.addMfaTokenUnlocked(r, enrollment, func() error {
			if err := target.commitUnlocked(); err != nil {
				return err
			}
			db.adoptMfaMutationSnapshot(target)
			return nil
		})
	})
}

func (db *Database) indexMfaMutationSnapshot() error {
	db.Version = app.Version
	db.enforceDefaultPolicy()
	db.refUsername = make(map[string]*User)
	db.refID = make(map[string]*User)
	db.refEmailAddress = make(map[string]*User)
	db.refAPIKey = make(map[string]*User)
	for _, user := range db.Users {
		if user == nil {
			return fmt.Errorf("nil user in persisted database")
		}
		if err := user.Valid(); err != nil {
			return err
		}
		username := strings.ToLower(user.Username)
		if _, exists := db.refUsername[username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		if _, exists := db.refID[user.ID]; exists {
			return fmt.Errorf("duplicate user ID %q", user.ID)
		}
		db.refUsername[username] = user
		db.refID[user.ID] = user
		for _, password := range user.Passwords {
			if password != nil && password.Algorithm == "" {
				password.Algorithm = "bcrypt"
			}
		}
		for _, email := range user.EmailAddresses {
			if email == nil {
				continue
			}
			address := strings.ToLower(email.Address)
			if _, exists := db.refEmailAddress[address]; exists {
				return fmt.Errorf("duplicate email address %q", email.Address)
			}
			db.refEmailAddress[address] = user
		}
		for _, key := range user.APIKeys {
			if key == nil {
				continue
			}
			if _, exists := db.refAPIKey[key.Prefix]; exists {
				return fmt.Errorf("duplicate API key prefix %q", key.Prefix)
			}
			db.refAPIKey[key.Prefix] = user
		}
	}
	return nil
}

func (db *Database) adoptMfaMutationSnapshot(target *Database) {
	db.Version = target.Version
	db.Policy = target.Policy
	db.Revision = target.Revision
	db.LastModified = target.LastModified
	db.Users = target.Users
	db.refUsername = target.refUsername
	db.refID = target.refID
	db.refEmailAddress = target.refEmailAddress
	db.refAPIKey = target.refAPIKey
}

func (db *Database) validateMfaTokenMutationEvidence(proof requests.AuthenticationEvidence, user *User) (bool, error) {
	bound := authenticationEvidenceBound(proof)
	if !bound {
		return false, nil
	}
	if !db.authenticationEvidenceMatches(proof, user) {
		return true, errors.ErrAddMfaToken.WithArgs("authentication evidence no longer matches the identity")
	}
	return true, nil
}

func authenticationEvidenceBound(proof requests.AuthenticationEvidence) bool {
	return proof.UserID != "" || proof.BackendVersion != "" || proof.CredentialVersion != 0 ||
		proof.AuthenticatedAt != 0 || proof.Method != ""
}

func (db *Database) authenticationEvidenceMatches(proof requests.AuthenticationEvidence, user *User) bool {
	return proof.UserID != "" && proof.BackendVersion != "" && user != nil && !user.Disabled &&
		proof.UserID == user.ID && proof.CredentialVersion == user.CredentialVersion &&
		proof.BackendVersion == db.LoadedAt.Format(time.RFC3339Nano)
}

func (db *Database) addMfaTokenUnlocked(r *requests.Request, enrollment bool, commit func() error) error {
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrAddMfaToken.WithArgs(err)
	}
	if enrollment {
		for _, token := range user.MfaTokens {
			if token != nil && !token.Disabled {
				return errors.ErrAddMfaToken.WithArgs("an enabled MFA factor already exists")
			}
		}
	}
	previousTokens := append([]*MfaToken(nil), user.MfaTokens...)
	previousCredentialVersion := user.CredentialVersion
	previousUserRevision := user.Revision
	previousUserLastModified := user.LastModified
	previousDatabaseRevision := db.Revision
	previousDatabaseLastModified := db.LastModified
	if err := user.AddMfaToken(r); err != nil {
		return err
	}
	user.CredentialVersion++
	if err := commit(); err != nil {
		if slices.Contains(db.Users, user) {
			user.MfaTokens = previousTokens
			user.CredentialVersion = previousCredentialVersion
			user.Revision = previousUserRevision
			user.LastModified = previousUserLastModified
			db.Revision = previousDatabaseRevision
			db.LastModified = previousDatabaseLastModified
		}
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
			if !r.MfaToken.IncludeAll {
				continue
			}
		}
		copy := *token
		if copy.LastTOTPCounter != nil {
			counter := *copy.LastTOTPCounter
			copy.LastTOTPCounter = &counter
		}
		bundle.Add(&copy)
	}
	r.Response.Payload = bundle
	return nil
}

// GetMfaToken returns a single MFA token associated with a user.
func (db *Database) GetMfaToken(r *requests.Request) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	user, err := db.validateUserIdentity(r.User.Username, r.User.Email)
	if err != nil {
		return errors.ErrGetMfaTokens.WithArgs(err)
	}
	for _, token := range user.MfaTokens {
		if token.Disabled {
			if !r.MfaToken.IncludeAll {
				continue
			}
		}
		if token.ID != r.MfaToken.ID {
			continue
		}
		copy := *token
		if copy.LastTOTPCounter != nil {
			counter := *copy.LastTOTPCounter
			copy.LastTOTPCounter = &counter
		}
		r.Response.Payload = &copy
		return nil
	}
	return errors.ErrGetMfaToken.WithArgs("not found")
}

// ConsumeMfaTOTP validates and atomically consumes a TOTP time step for a
// user's enabled factors.
func (db *Database) ConsumeMfaTOTP(r *requests.Request) error {
	return db.consumeMfaTOTPWithTime(r, time.Now().UTC())
}

func (db *Database) consumeMfaTOTPWithTime(r *requests.Request, ts time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.inMemory {
		return db.consumeMfaTOTPUnlocked(r, ts, db.commitUnlocked)
	}
	err := withDatabaseFileLock(db.path, func() error {
		data, err := os.ReadFile(db.path)
		if err != nil {
			return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
		}
		target := &Database{path: db.path}
		if err := json.Unmarshal(data, target); err != nil {
			return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
		}
		if err := target.indexMfaMutationSnapshot(); err != nil {
			return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
		}
		cachedUser, cachedErr := db.validateUserIdentity(r.User.Username, r.User.Email)
		currentUser, currentErr := target.validateUserIdentity(r.User.Username, r.User.Email)
		if cachedErr != nil || currentErr != nil || cachedUser.ID != currentUser.ID ||
			cachedUser.CredentialVersion != currentUser.CredentialVersion {
			db.adoptMfaMutationSnapshot(target)
			db.LoadedAt = time.Now().UTC()
			return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
		}
		target.LoadedAt = db.LoadedAt
		return target.consumeMfaTOTPUnlocked(r, ts, func() error {
			if err := target.commitUnlocked(); err != nil {
				return err
			}
			db.adoptMfaMutationSnapshot(target)
			return nil
		})
	})
	if err != nil {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
	}
	return nil
}

func (db *Database) consumeMfaTOTPUnlocked(r *requests.Request, ts time.Time, commit func() error) error {
	user, err := db.findUserIdentity(r.User.Username, r.User.Email)
	if err != nil || user.Disabled || user.Lockout != nil && user.Lockout.IsLocked() ||
		authenticationEvidenceBound(r.Authentication) && !db.authenticationEvidenceMatches(r.Authentication, user) {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
	}
	var consumedToken *MfaToken
	var consumedCounter uint64
	for _, token := range user.MfaTokens {
		if token == nil {
			continue
		}
		if token.Type != "totp" || token.Disabled || token.Expired {
			continue
		}
		counter, err := token.matchCodeWithTime(r.MfaToken.Passcode, ts)
		if err != nil {
			continue
		}
		if token.LastTOTPCounter != nil && counter <= *token.LastTOTPCounter {
			continue
		}
		consumedToken = token
		consumedCounter = counter
		break
	}
	if consumedToken == nil {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
	}
	previousCounter := consumedToken.LastTOTPCounter
	consumedToken.LastTOTPCounter = &consumedCounter
	if err := commit(); err != nil {
		consumedToken.LastTOTPCounter = previousCounter
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
	}
	return nil
}

func (db *Database) findUserIdentity(username, email string) (*User, error) {
	var usernameUser, emailUser *User
	for _, user := range db.Users {
		if user == nil {
			continue
		}
		if strings.EqualFold(user.Username, username) {
			usernameUser = user
		}
		for _, address := range user.EmailAddresses {
			if address == nil {
				continue
			}
			if strings.EqualFold(address.Address, email) {
				emailUser = user
				break
			}
		}
	}
	if usernameUser == nil || emailUser == nil {
		return nil, errors.ErrDatabaseUserNotFound
	}
	if usernameUser.ID != emailUser.ID {
		return nil, errors.ErrDatabaseInvalidUser
	}
	return usernameUser, nil
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
	user.CredentialVersion++
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
	user1 := db.refUsername[username]
	user2 := db.refEmailAddress[emailAddress]
	switch {
	case user1 == nil && user2 == nil:
		return false, nil
	case user1 == nil:
		return false, fmt.Errorf("email is registered to a user, while username not found")
	case user2 == nil:
		return false, fmt.Errorf("username is registered to a user, while email not found (username: %s, email: %s)", username, emailAddress)
	}
	if user1.ID != user2.ID {
		return false, fmt.Errorf("username and email address belong to two different users")
	}
	return true, nil
}

// GetMetadata returns Database metadata.
func (db *Database) GetMetadata() map[string]any {
	return map[string]any{
		"version":       db.Version,
		"policy":        db.Policy,
		"revision":      db.Revision,
		"last_modified": db.LastModified,
		"loaded_at":     db.LoadedAt,
		"user_count":    len(db.Users),
		"path":          db.path,
		"in_memory":     db.inMemory,
	}
}

// Reload reloads Database instance.
func (db *Database) Reload() error {
	return nil
}

// GeneratePassword generates random password based on database password policies.
func (db *Database) GeneratePassword() string {
	policy := db.Policy.Password

	// Define character sets
	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers := "0123456789"
	special := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	var charPool string
	var password []byte

	// Ensure at least one character from each required category is present
	// to satisfy the policy immediately.
	addChar := func(set string) {
		if len(set) > 0 {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
			password = append(password, set[n.Int64()])
		}
	}

	// Always include lowercase by default unless you want to be ultra-strict,
	// but we'll use the policy flags to build the pool.
	charPool += lower
	if policy.RequireUppercase {
		charPool += upper
		addChar(upper)
	}
	if policy.RequireNumber {
		charPool += numbers
		addChar(numbers)
	}
	if policy.RequireNonAlphaNumeric {
		charPool += special
		addChar(special)
	}

	// If no specific requirements, expand pool to everything for better entropy
	if !policy.RequireUppercase && !policy.RequireNumber && !policy.RequireNonAlphaNumeric {
		charPool += upper + numbers
	}

	// Fill the remaining length
	length := policy.MinLength
	if length < 8 {
		length = 8 // Sensible default if policy is too loose
	}
	if length > policy.MaxLength && policy.MaxLength > 0 {
		length = policy.MaxLength
	}

	for len(password) < length {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charPool))))
		password = append(password, charPool[n.Int64()])
	}

	// Shuffle the slice so required characters aren't always at the start
	for i := len(password) - 1; i > 0; i-- {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := n.Int64()
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}
