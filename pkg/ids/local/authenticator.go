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

package local

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

const (
	defaultAdminRoleName = "authp/admin"
)

// Authenticator represents database connector.
type Authenticator struct {
	db     *identity.Database
	mux    sync.Mutex
	path   string
	logger *zap.Logger
}

// NewAuthenticator returns an instance of Authenticator.
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

// Configure check database connectivity and required tables.
func (sa *Authenticator) Configure(fp string, users []*User) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	sa.logger.Info(
		"identity store authenticator configuration",
		zap.String("kind", storeKind),
		zap.String("db_path", fp),
	)
	sa.path = fp

	db, err := identity.NewDatabase(fp)
	if err != nil {
		return err
	}
	sa.db = db

	if len(users) > 0 {
		for _, user := range users {
			// Check whether user exists.
			userFound, err := sa.db.UserExists(user.Username, user.EmailAddress)
			if err != nil {
				return err
			}
			if !userFound {
				sa.logger.Debug(
					"creating statically-defined identity store user",
					zap.String("user", user.Username),
					zap.String("email", user.EmailAddress),
				)
				// Create user.
				req := &requests.Request{
					User: requests.User{
						Username: user.Username,
						Password: user.Password,
						Email:    user.EmailAddress,
						Roles:    user.Roles,
						FullName: user.Name,
					},
				}
				if err := sa.db.AddUser(req); err != nil {
					return err
				}
			} else {
				if user.PasswordOverwriteEnabled {
					sa.logger.Debug(
						"updating password for statically-defined identity store user",
						zap.String("user", user.Username),
						zap.String("email", user.EmailAddress),
					)
					// Update password (if overwrite is enabled).
					req := &requests.Request{
						User: requests.User{
							Username: user.Username,
							Password: user.Password,
							Email:    user.EmailAddress,
						},
					}
					if err := sa.db.UpdateUserPassword(req); err != nil {
						return err
					}
				}
			}

			if len(user.APIKeys) > 0 {
				sa.logger.Debug(
					"updating api keys for statically-defined identity store user",
					zap.String("user", user.Username),
					zap.String("email", user.EmailAddress),
					zap.Int("api_key_count", len(user.APIKeys)),
				)
				for _, key := range user.APIKeys {
					if len(key.ID) != 24 {
						return fmt.Errorf("provided api key id is not 24 characters long")
					}
					req := &requests.Request{
						User: requests.User{
							Username: user.Username,
							Email:    user.EmailAddress,
						},
						Key: requests.Key{
							Usage:   "api",
							Prefix:  key.ID,
							Payload: key.Payload,
						},
					}
					if err := sa.db.AddAPIKey(req); err != nil {
						return err
					}
				}
			}
		}
	}

	if sa.db.GetAdminUserCount() < 1 {
		req := &requests.Request{
			User: requests.User{
				Username: os.Getenv("AUTHP_ADMIN_USER"),
				Password: os.Getenv("AUTHP_ADMIN_SECRET"),
				Email:    os.Getenv("AUTHP_ADMIN_EMAIL"),
				Roles:    []string{defaultAdminRoleName},
			},
		}

		if req.User.Username == "" {
			req.User.Username = "webadmin"
		}

		if req.User.Password == "" {
			req.User.Password = uuid.New().String()
		}

		if req.User.Email == "" {
			req.User.Email = "webadmin@localdomain.local"
		}

		if err := sa.db.AddUser(req); err != nil {
			return err
		}
		sa.logger.Info("created default admin user for the database",
			zap.String("username", req.User.Username),
			zap.String("email", req.User.Email),
			zap.Any("roles", req.User.Roles),
		)
	}
	return nil
}

// Reload reloads the database.
func (sa *Authenticator) Reload() error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	db, err := identity.NewDatabase(sa.path)
	if err != nil {
		return err
	}
	sa.db = db
	return nil
}

// AuthenticateUser checks the database for the presence of a username/email
// and password and returns user claims.
func (sa *Authenticator) AuthenticateUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AuthenticateUser(r)
}

// AddUser adds a user to database.
func (sa *Authenticator) AddUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if r.User.Password == "" {
		r.User.Password = sa.db.GeneratePassword()
	}
	return sa.db.AddUser(r)
}

// OverwriteUserRoles overwrites user roles in IdentityStore.
func (sa *Authenticator) OverwriteUserRoles(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.OverwriteUserRoles(r)
}

// AddUserRoles adds user roles to IdentityStore.
func (sa *Authenticator) AddUserRoles(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddUserRoles(r)
}

// ResetUserPassword resets user password in database.
func (sa *Authenticator) ResetUserPassword(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	if r.User.Password == "" {
		r.User.Password = sa.db.GeneratePassword()
	}
	return sa.db.ResetUserPassword(r)
}

// GetUsers retrieves users from database.
func (sa *Authenticator) GetUsers(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetUsers(r)
}

// ListUsers retrieves users from database.
func (sa *Authenticator) ListUsers() []map[string]any {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.ListUsers()
}

// FetchUserData retrieves user data from database.
func (sa *Authenticator) FetchUserData(username string, emailAddress string) (map[string]any, error) {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	req := &requests.Request{
		User: requests.User{
			Username: username,
			Email:    emailAddress,
		},
	}
	if err := sa.db.GetUser(req); err != nil {
		return nil, err
	}
	if req.Response.Payload != nil {
		if u, ok := req.Response.Payload.(*identity.User); ok {
			return u.AsMap(), nil
		}
	}
	return nil, fmt.Errorf("response had no user info")
}

// GetUser retrieves a specific user from database.
func (sa *Authenticator) GetUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetUser(r)
}

// DeleteUser delete a specific user from database.
func (sa *Authenticator) DeleteUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeleteUser(r)
}

// DisableUser disables a specific user from database.
func (sa *Authenticator) DisableUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DisableUser(r)
}

// EnableUser enables a specific user in database.
func (sa *Authenticator) EnableUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.EnableUser(r)
}

// ChangePassword changes password for a user.
func (sa *Authenticator) ChangePassword(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.ChangeUserPassword(r)
}

// AddPublicKey adds public key, e.g. GPG or SSH, for a user.
func (sa *Authenticator) AddPublicKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddPublicKey(r)
}

// DeletePublicKey removes a public key, e.g. GPG or SSH, associated with the user.
func (sa *Authenticator) DeletePublicKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeletePublicKey(r)
}

// GetPublicKeys returns a list of public keys associated with a user.
func (sa *Authenticator) GetPublicKeys(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetPublicKeys(r)
}

// GetPublicKey returns a public keys associated with a user.
func (sa *Authenticator) GetPublicKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetPublicKey(r)
}

// AddAPIKey adds API key for a user.
func (sa *Authenticator) AddAPIKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddAPIKey(r)
}

// DeleteAPIKey removes API key associated with the user.
func (sa *Authenticator) DeleteAPIKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeleteAPIKey(r)
}

// GetAPIKeys returns a list of  API keys associated with a user.
func (sa *Authenticator) GetAPIKeys(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetAPIKeys(r)
}

// GetAPIKey returns API key associated with a user.
func (sa *Authenticator) GetAPIKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetAPIKey(r)
}

// AddMfaToken adds MFA token to a user.
func (sa *Authenticator) AddMfaToken(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.AddMfaToken(r)
}

// DeleteMfaToken removes MFA token associated with the user.
func (sa *Authenticator) DeleteMfaToken(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.DeleteMfaToken(r)
}

// GetMfaTokens returns a list of MFA token associated with a user.
func (sa *Authenticator) GetMfaTokens(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetMfaTokens(r)
}

// GetMfaToken returns a single MFA token associated with a user.
func (sa *Authenticator) GetMfaToken(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetMfaToken(r)
}

// IdentifyUser returns user challenges.
func (sa *Authenticator) IdentifyUser(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.IdentifyUser(r)
}

// LookupAPIKey performs user lookup based on an API key.
func (sa *Authenticator) LookupAPIKey(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.LookupAPIKey(r)
}

// GetMetadata returns metadata associated with the Authenticator database.
func (sa *Authenticator) GetMetadata() map[string]any {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.GetMetadata()
}

// CheckMfaLockout checks whether a user is locked out due to too many
// failed MFA attempts.
func (sa *Authenticator) CheckMfaLockout(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.CheckMfaLockout(r)
}

// IncrementMfaFailedAttempts increments the MFA failed attempt counter.
func (sa *Authenticator) IncrementMfaFailedAttempts(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.IncrementMfaFailedAttempts(r)
}

// ResetMfaFailedAttempts resets the MFA failed attempt counter.
func (sa *Authenticator) ResetMfaFailedAttempts(r *requests.Request) error {
	sa.mux.Lock()
	defer sa.mux.Unlock()
	return sa.db.ResetMfaFailedAttempts(r)
}
