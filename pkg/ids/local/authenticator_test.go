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
	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"os"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	db, err := testutils.CreateTestDatabase("TestLocalIdentityStore")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := db.GetPath()

	config := &Config{
		Name:  "local_store",
		Realm: "local",
		Path:  dbPath,
	}

	testcases := []struct {
		name      string
		config    *Config
		op        operator.Type
		req       *requests.Request
		opts      map[string]interface{}
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:   "authenticate user",
			config: config,
			op:     operator.Authenticate,
			req: &requests.Request{
				User: requests.User{
					Username: tests.TestUser1,
					Email:    tests.TestEmail1,
					Password: tests.TestPwd1,
				},
			},
			want: map[string]interface{}{
				"config": map[string]interface{}{
					"name":  "local_store",
					"realm": "local",
					"path":  dbPath,
				},
			},
		},
		{
			name:   "authenticate user with invalid password",
			config: config,
			op:     operator.Authenticate,
			req: &requests.Request{
				User: requests.User{
					Username: tests.TestUser1,
					Email:    tests.TestEmail1,
				},
			},
			shouldErr: true,
			err:       errors.ErrIdentityStoreLocalAuthFailed.WithArgs("user authentication failed: malformed auth request"),
		},
		{
			name:      "test unknown operator",
			config:    config,
			op:        operator.Unknown,
			shouldErr: true,
			err:       errors.ErrOperatorNotSupported.WithArgs(operator.Unknown),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("db path: %v", tc.config.Path))
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			logger := logutil.NewLogger()

			b, err := NewIdentityStore(tc.config, logger)
			if err != nil {
				t.Fatalf("initialization error: %v", err)
			}

			if err := b.Configure(); err != nil {
				t.Fatalf("configuration error: %v", err)
			}

			err = b.Request(tc.op, tc.req)
			if tests.EvalErrWithLog(t, err, "authenticate", tc.shouldErr, tc.err, msgs) {
				return
			}

			got := make(map[string]interface{})
			got["config"] = b.GetConfig()
			tests.EvalObjectsWithLog(t, "user", tc.want, got, msgs)
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	testcases := []struct {
		name         string
		config       *Config
		db           func() *identity.Database
		env          map[string]string
		authenticate bool
		want         map[string]interface{}
		shouldErr    bool
		err          error
	}{
		{
			name: "test new authenticator with user env var",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
			},
			env: map[string]string{
				"AUTHP_ADMIN_USER":   "myadmin",
				"AUTHP_ADMIN_SECRET": uuid.New().String(),
				"AUTHP_ADMIN_EMAIL":  "myadmin@localdomain.local",
			},
			db: func() *identity.Database {
				db, err := testutils.CreateEmptyTestDatabase("TestLocalIdentityStore")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				return db
			},
			authenticate: true,
			want: map[string]interface{}{
				"response": requests.Response{
					Code: 200,
				},
			},
		},
		{
			name: "test new authenticator without user env var",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
			},
			db: func() *identity.Database {
				db, err := testutils.CreateEmptyTestDatabase("TestLocalIdentityStore")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				return db
			},
			want: map[string]interface{}{},
		},
		{
			name: "test new authenticator with invalid user email",
			config: &Config{
				Name:  "local_store",
				Realm: "local",
			},
			env: map[string]string{
				"AUTHP_ADMIN_USER":   "myadmin",
				"AUTHP_ADMIN_SECRET": uuid.New().String(),
				"AUTHP_ADMIN_EMAIL":  "localdomain.local",
			},
			db: func() *identity.Database {
				db, err := testutils.CreateEmptyTestDatabase("TestLocalIdentityStore")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				return db
			},
			shouldErr: true,
			err:       errors.ErrAddUser.WithArgs("myadmin", "invalid email address"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			for k, v := range tc.env {
				msgs = append(msgs, fmt.Sprintf("env: %s = %s", k, v))
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			db := tc.db()
			tc.config.Path = db.GetPath()
			msgs = append(msgs, fmt.Sprintf("db path: %v", tc.config.Path))
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			b := NewAuthenticator()
			b.logger = logutil.NewLogger()
			err := b.Configure(db.GetPath())
			if tests.EvalErrWithLog(t, err, "configure", tc.shouldErr, tc.err, msgs) {
				return
			}

			req := &requests.Request{
				User: requests.User{
					Username: os.Getenv("AUTHP_ADMIN_USER"),
					Email:    os.Getenv("AUTHP_ADMIN_EMAIL"),
					Password: os.Getenv("AUTHP_ADMIN_SECRET"),
				},
			}

			if tc.authenticate {
				err = b.AuthenticateUser(req)
				if tests.EvalErrWithLog(t, err, "authenticate", tc.shouldErr, tc.err, msgs) {
					return
				}

				got := make(map[string]interface{})
				got["response"] = req.Response
				tests.EvalObjectsWithLog(t, "user", tc.want, got, msgs)
			}
		})
	}
}
