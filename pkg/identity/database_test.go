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
	"fmt"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

var (
	testUser1     = "jsmith"
	testEmail1    = "jsmith@gmail.com"
	testPwd1      = tests.NewRandomString(12)
	testFullName1 = "Smith, John"
	testRoles1    = []string{"viewer", "editor", "admin"}
	testUser2     = "bjones"
	testEmail2    = "bjones@gmail.com"
	testPwd2      = tests.NewRandomString(16)
	testFullName2 = ""
	testRoles2    = []string{"viewer"}
)

func createTestDatabase(s string) (*Database, error) {
	tmpDir, err := tests.TempDir(s)
	if err != nil {
		return nil, err
	}
	reqs := []*requests.Request{
		{
			User: requests.User{
				Username: testUser1,
				Password: testPwd1,
				Email:    testEmail1,
				FullName: testFullName1,
				Roles:    testRoles1,
			},
		},
		{
			User: requests.User{
				Username: testUser2,
				Password: testPwd2,
				Email:    testEmail2,
				FullName: testFullName2,
				Roles:    testRoles2,
			},
		},
	}

	db, err := NewDatabase(filepath.Join(tmpDir, "user_db.json"))
	if err != nil {
		return nil, err
	}

	for _, req := range reqs {
		if err := db.AddUser(req); err != nil {
			return nil, err
		}
		user, err := db.getUser(req.User.Username)
		if err != nil {
			return nil, err
		}
		user.PublicKeys = append(user.PublicKeys, &PublicKey{})
	}
	return db, nil
}

func TestNewDatabase(t *testing.T) {
	tmpDir, err := tests.TempDir("TestNewDatabase")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Logf("%v", tmpDir)
	passwd := tests.NewRandomString(12)
	testcases := []struct {
		name      string
		path      string
		req       *requests.Request
		backup    string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test create new database",
			path: filepath.Join(tmpDir, "user_db.json"),
			req: &requests.Request{
				User: requests.User{
					Username: "jsmith",
					Password: passwd,
					Email:    "jsmith@gmail.com",
					FullName: "Smith, John",
					Roles:    []string{"viewer", "editor", "admin"},
				},
			},
			backup: filepath.Join(tmpDir, "user_db_backup.json"),
			want: map[string]interface{}{
				"path":       filepath.Join(tmpDir, "user_db.json"),
				"user_count": 0,
			},
		},
		{
			name: "test create new in-memory database",
			path: ":memory:",
			req: &requests.Request{
				User: requests.User{
					Username: "jsmith",
					Password: passwd,
					Email:    "jsmith@gmail.com",
					FullName: "Smith, John",
					Roles:    []string{"viewer", "editor", "admin"},
				},
			},
			backup: filepath.Join(tmpDir, "user_db_backup.json"),
			want: map[string]interface{}{
				"path":       ":memory:",
				"user_count": 0,
			},
		},
		{
			name: "test new database is directory",
			path: tmpDir,
			want: map[string]interface{}{
				"path": tmpDir,
			},
			shouldErr: true,
			err:       errors.ErrNewDatabase.WithArgs(tmpDir, "path points to a directory"),
		},
		{
			name: "test load new database",
			path: filepath.Join(tmpDir, "user_db.json"),
			want: map[string]interface{}{
				"path":       filepath.Join(tmpDir, "user_db.json"),
				"user_count": 1,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("temporary directory: %s", tmpDir))
			db, err := NewDatabase(tc.path)
			if tests.EvalErrWithLog(t, err, "new database", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["path"] = db.GetPath()
			got["user_count"] = db.GetUserCount()
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
			if tc.req != nil {
				if err := db.AddUser(tc.req); err != nil {
					tests.EvalErrWithLog(t, err, "add user", tc.shouldErr, tc.err, msgs)
				}
			}
			if err := db.Save(); err != nil {
				t.Fatal(err)
			}
			if tc.backup != "" {
				if err := db.Copy(tc.backup); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDatabaseAuthentication(t *testing.T) {
	db, err := createTestDatabase("TestDatabaseAuthentication")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	// t.Logf("%v", db.path)

	testcases := []struct {
		name      string
		req       *requests.Request
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "authenticate user1 with username",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Password: testPwd1,
				},
				Upstream: requests.Upstream{
					BaseURL:  "https://localhost",
					BasePath: "/auth",
					Method:   "local",
					Realm:    "local",
				},
			},
			want: map[string]interface{}{
				"code":       200,
				"email":      "jsmith@gmail.com",
				"name":       "Smith, John",
				"roles":      []string{"viewer", "editor", "admin"},
				"sub":        "jsmith",
				"challenges": []string{"password"},
			},
		},
		{
			name: "authenticate user2 with username",
			req: &requests.Request{
				User: requests.User{
					Username: testUser2,
					Password: testPwd2,
				},
				Flags: requests.Flags{
					Enabled: true,
				},
				Upstream: requests.Upstream{
					BaseURL:  "https://localhost",
					BasePath: "/auth",
					Method:   "local",
					Realm:    "local",
				},
			},
			want: map[string]interface{}{
				"code":       200,
				"email":      "bjones@gmail.com",
				"roles":      []string{"viewer"},
				"sub":        "bjones",
				"challenges": []string{"password"},
			},
		},
		{
			name: "authenticate user1 with email address",
			req: &requests.Request{
				User: requests.User{
					Username: testEmail1,
					Password: testPwd1,
				},
				Upstream: requests.Upstream{
					BaseURL:  "https://localhost",
					BasePath: "/auth",
					Method:   "local",
					Realm:    "local",
				},
			},
			want: map[string]interface{}{
				"code":       200,
				"email":      "jsmith@gmail.com",
				"name":       "Smith, John",
				"roles":      []string{"viewer", "editor", "admin"},
				"sub":        "jsmith",
				"challenges": []string{"password"},
			},
		},
		{
			name: "authenticate user2 with email address",
			req: &requests.Request{
				User: requests.User{
					Username: testEmail2,
					Password: testPwd2,
				},
				Upstream: requests.Upstream{
					BaseURL:  "https://localhost",
					BasePath: "/auth",
					Method:   "local",
					Realm:    "local",
				},
			},
			want: map[string]interface{}{
				"code":       200,
				"email":      "bjones@gmail.com",
				"roles":      []string{"viewer"},
				"sub":        "bjones",
				"challenges": []string{"password"},
			},
		},
		{
			name: "authenticate user1 with username and invalid password",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Password: testPwd2,
				},
				Upstream: requests.Upstream{
					BaseURL:  "https://localhost",
					BasePath: "/auth",
					Method:   "local",
					Realm:    "local",
				},
			},
			shouldErr: true,
			err:       errors.ErrAuthFailed.WithArgs(errors.ErrUserPasswordInvalid),
		},
		{
			name: "authenticate user1 with email address and invalid password",
			req: &requests.Request{
				User: requests.User{
					Username: testEmail1,
					Password: testPwd2,
				},
			},
			shouldErr: true,
			err:       errors.ErrAuthFailed.WithArgs(errors.ErrUserPasswordInvalid),
		},
		{
			name: "authenticate with invalid username",
			req: &requests.Request{
				User: requests.User{
					Username: "foobar",
					Password: "barfoo",
				},
			},
			shouldErr: true,
			err:       errors.ErrAuthFailed.WithArgs(errors.ErrDatabaseUserNotFound),
		},
		{
			name: "perform dummy authentication",
			req: &requests.Request{
				User: requests.User{
					Username: "foobar",
					Password: "barfoo",
				},
			},
			shouldErr: true,
			err:       errors.ErrAuthFailed.WithArgs(errors.ErrDatabaseUserNotFound),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			err = db.IdentifyUser(tc.req)

			got["sub"] = tc.req.User.Username
			got["email"] = tc.req.User.Email
			if tc.req.User.FullName != "" {
				got["name"] = tc.req.User.FullName
			}
			got["roles"] = tc.req.User.Roles
			got["challenges"] = tc.req.User.Challenges

			err = db.AuthenticateUser(tc.req)
			if tests.EvalErrWithLog(t, err, "authenticate", tc.shouldErr, tc.err, msgs) {
				return
			}
			got["code"] = tc.req.Response.Code
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)

			user, err := db.getUser(tc.req.User.Username)
			if err != nil {
				t.Fatal(err)
			}
			userByID, err := db.getUserByID(user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(user, userByID, cmp.AllowUnexported(User{}, EmailAddress{})); diff != "" {
				tests.WriteLog(t, msgs)
				t.Fatalf("user by username and id mismatch (-want +got):\n%s", diff)
			}

			_, err = db.getUserByID("foobar")
			if tests.EvalErrWithLog(t, err, "authenticate", true, errors.ErrDatabaseUserNotFound, msgs) {
				return
			}
		})
	}
}

func TestDatabaseAddUser(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabaseAddUser")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	databasePath = db.path
	// t.Logf("%v", db.path)
	testcases := []struct {
		name          string
		req           *requests.Request
		overwritePath string
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name: "add user with used username",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Password: testPwd1,
					Email:    testEmail1,
					FullName: testFullName1,
					Roles:    testRoles1,
				},
			},
			shouldErr: true,
			err:       errors.ErrAddUser.WithArgs(testUser1, "username already in use"),
		},
		{
			name: "add user with empty username",
			req: &requests.Request{
				User: requests.User{
					Username: "",
					Email:    "foobar@barfoo",
				},
			},
			shouldErr: true,
			err:       errors.ErrAddUser.WithArgs("", errors.ErrUserPolicyCompliance),
		},
		{
			name: "add user with used email",
			req: &requests.Request{
				User: requests.User{
					Username: "foobar",
					Password: testPwd1,
					Email:    testEmail1,
					FullName: testFullName1,
					Roles:    testRoles1,
				},
			},
			shouldErr: true,
			err:       errors.ErrAddUser.WithArgs(testEmail1, "email address already in use"),
		},

		{
			name: "fail committing after adding new user",
			req: &requests.Request{
				User: requests.User{
					Username: "foobar",
					Password: tests.NewRandomString(16),
					Email:    "foobar@barfoo",
				},
			},
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrAddUser.WithArgs("foobar",
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			db.path = databasePath
			if tc.overwritePath != "" {
				db.path = tc.overwritePath
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			err = db.AddUser(tc.req)
			if tests.EvalErrWithLog(t, err, "add user", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["user_count"] = len(db.Users)
			tests.EvalObjectsWithLog(t, "user passwords", tc.want, got, msgs)
		})
	}
}

func TestDatabaseChangeUserPassword(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabaseChangeUserPassword")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	databasePath = db.path
	// t.Logf("%v", db.path)
	testcases := []struct {
		name          string
		req           *requests.Request
		overwritePath string
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name: "change user1 password with invalid current password",
			req: &requests.Request{
				User: requests.User{
					Username:    testUser1,
					Email:       testEmail1,
					OldPassword: "foobar",
					Password:    tests.NewRandomString(16),
				},
			},
			shouldErr: true,
			err:       errors.ErrChangeUserPassword.WithArgs(errors.ErrUserPasswordInvalid),
		},
		{
			name: "change user1 password",
			req: &requests.Request{
				User: requests.User{
					Username:    testUser1,
					Email:       testEmail1,
					OldPassword: testPwd1,
					Password:    tests.NewRandomString(16),
				},
			},
			want: map[string]interface{}{
				"password_count": 2,
			},
		},
		{
			name: "change password of invalid user",
			req: &requests.Request{
				User: requests.User{
					Username:    "foobar",
					Email:       "foobar@barfoo",
					OldPassword: "foobar",
					Password:    tests.NewRandomString(16),
				},
			},
			shouldErr: true,
			err:       errors.ErrChangeUserPassword.WithArgs(errors.ErrDatabaseUserNotFound),
		},
		{
			name: "fail committing after change user2 password",
			req: &requests.Request{
				User: requests.User{
					Username:    testUser2,
					Email:       testEmail2,
					OldPassword: testPwd2,
					Password:    tests.NewRandomString(16),
				},
			},
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrChangeUserPassword.WithArgs(
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			db.path = databasePath
			if tc.overwritePath != "" {
				db.path = tc.overwritePath
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))

			err = db.ChangeUserPassword(tc.req)
			if tests.EvalErrWithLog(t, err, "change password", tc.shouldErr, tc.err, msgs) {
				return
			}

			req := &requests.Request{User: requests.User{Username: tc.req.User.Username, Password: tc.req.User.Password}}
			if err := db.AuthenticateUser(req); err != nil {
				t.Fatalf("expected authentication success, but got failure: %v", err)
			}

			user, err := db.getUser(tc.req.User.Username)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]interface{})
			got["password_count"] = len(user.Passwords)
			tests.EvalObjectsWithLog(t, "user passwords", tc.want, got, msgs)
		})
	}
}

func TestDatabaseUserPublicKey(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabaseUserPublicKey")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	databasePath = db.path
	testcases := []struct {
		name           string
		operation      string
		usage          string
		overwriteUsage string
		overwritePath  string
		keyID          string
		keyAlgorithm   string
		pubKeyType     string
		comment        string
		username       string
		email          string
		want           map[string]interface{}
		shouldErr      bool
		err            error
	}{
		{
			name:         "add disabled openssh public key",
			operation:    "add",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			comment:      testEmail1,
			username:     testUser1,
			email:        testEmail1,
			want: map[string]interface{}{
				"key_count": 1,
			},
		},

		{
			name:         "add openssh public key",
			operation:    "add",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			comment:      testEmail1,
			username:     testUser1,
			email:        testEmail1,
			want: map[string]interface{}{
				"key_count": 2,
			},
		},
		{
			name:         "add rsa public key",
			operation:    "add",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			comment:      testEmail1,
			username:     testUser1,
			email:        testEmail1,
			want: map[string]interface{}{
				"key_count": 3,
			},
		},
		{
			name:      "delete all public keys",
			operation: "delete",
			username:  testUser1,
			email:     testEmail1,
			usage:     "ssh",
			want: map[string]interface{}{
				"key_count": 0,
			},
		},
		{
			name:         "readd rsa public key",
			operation:    "add",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			comment:      testEmail1,
			username:     testUser1,
			email:        testEmail1,
			want: map[string]interface{}{
				"key_count": 1,
			},
		},
		{
			name:      "delete non-existing public key",
			operation: "delete",
			username:  testUser1,
			email:     testEmail1,
			usage:     "ssh",
			keyID:     "foobar",
			shouldErr: true,
			err:       errors.ErrDeletePublicKey.WithArgs("foobar", "not found"),
		},
		{
			name:         "add rsa public key with non-existing username",
			operation:    "add",
			username:     "foobar",
			email:        "foobar@barfoo",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			shouldErr:    true,
			err:          errors.ErrAddPublicKey.WithArgs("ssh", errors.ErrDatabaseUserNotFound),
		},
		{
			name:         "add rsa public key with mismatch user and email",
			operation:    "add",
			username:     testUser1,
			email:        testEmail2,
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			shouldErr:    true,
			err:          errors.ErrAddPublicKey.WithArgs("ssh", errors.ErrDatabaseInvalidUser),
		},
		{
			name:         "add rsa public key with non-existing email address",
			operation:    "add",
			username:     testUser1,
			email:        "foobar@barfoo",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			shouldErr:    true,
			err:          errors.ErrAddPublicKey.WithArgs("ssh", errors.ErrDatabaseUserNotFound),
		},
		{
			name:         "get public keys with non-existing email address",
			operation:    "get",
			username:     testUser1,
			email:        "foobar@barfoo",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			pubKeyType:   "openssh",
			shouldErr:    true,
			err:          errors.ErrGetPublicKeys.WithArgs("ssh", errors.ErrDatabaseUserNotFound),
		},

		{
			name:         "delete public key with non-existing email address",
			operation:    "delete",
			username:     testUser1,
			email:        "foobar@barfoo",
			usage:        "ssh",
			keyAlgorithm: "rsa",
			shouldErr:    true,
			keyID:        "barfoo",
			err:          errors.ErrDeletePublicKey.WithArgs("barfoo", errors.ErrDatabaseUserNotFound),
		},
		{
			name:           "add invalid public key usage",
			operation:      "add",
			username:       testUser1,
			email:          testEmail1,
			usage:          "ssh",
			overwriteUsage: "foobar",
			keyAlgorithm:   "rsa",
			pubKeyType:     "openssh",
			shouldErr:      true,
			err:            errors.ErrAddPublicKey.WithArgs("foobar", errors.ErrPublicKeyInvalidUsage.WithArgs("foobar")),
		},
		{
			name:          "fail to commit when adding rsa public key",
			operation:     "add",
			usage:         "ssh",
			keyAlgorithm:  "rsa",
			pubKeyType:    "openssh",
			comment:       testEmail1,
			username:      testUser1,
			email:         testEmail1,
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrAddPublicKey.WithArgs("ssh",
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
		{
			name:          "fail to commit when deleting rsa public key",
			operation:     "delete",
			username:      testUser1,
			email:         testEmail1,
			usage:         "ssh",
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrDeletePublicKey.WithArgs("ssh",
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			db.path = databasePath
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			switch tc.operation {
			case "add":
				r := requests.NewRequest()
				r.User.Username = tc.username
				r.User.Email = tc.email
				r.Key.Usage = tc.usage
				r.Key.Comment = tc.comment
				_, publicKey := tests.GetCryptoKeyPair(t, tc.keyAlgorithm, tc.pubKeyType)
				r.Key.Payload = publicKey
				if tc.overwriteUsage != "" {
					r.Key.Usage = tc.overwriteUsage
				}
				if tc.overwritePath != "" {
					db.path = tc.overwritePath
				}
				err = db.AddPublicKey(r)
				if tests.EvalErrWithLog(t, err, "add public key", tc.shouldErr, tc.err, msgs) {
					return
				}
			case "get":
			case "delete":
				r := requests.NewRequest()
				r.User.Username = tc.username
				r.User.Email = tc.email
				r.Key.Usage = tc.usage
				err = db.GetPublicKeys(r)
				if tc.keyID != "" {
					// Delete specific key.
					r.Key.ID = tc.keyID
					err = db.DeletePublicKey(r)
					if tests.EvalErrWithLog(t, err, "delete public key by id", tc.shouldErr, tc.err, msgs) {
						return
					}
					break
				}
				// Delete all keys.
				if tc.overwritePath != "" {
					db.path = tc.overwritePath
				}
				bundle := r.Response.Payload.(*PublicKeyBundle)
				var arr []string
				for _, k := range bundle.Get() {
					arr = append(arr, k.ID)
				}
				for _, k := range arr {
					r.Key.ID = k
					err = db.DeletePublicKey(r)
					if tests.EvalErrWithLog(t, err, "delete public key", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			case "":
				t.Fatal("empty test operation")
			default:
				t.Fatalf("unsupported test operation: %s", tc.operation)
			}

			r := requests.NewRequest()
			r.User.Username = tc.username
			r.User.Email = tc.email
			r.Key.Usage = tc.usage
			err = db.GetPublicKeys(r)
			if tests.EvalErrWithLog(t, err, "get public keys", tc.shouldErr, tc.err, msgs) {
				return
			}
			bundle := r.Response.Payload.(*PublicKeyBundle)
			got := make(map[string]interface{})
			got["key_count"] = bundle.Size()
			tests.EvalObjectsWithLog(t, "user", tc.want, got, msgs)
		})
	}
}

func TestDatabaseUserMfaToken(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabaseUserMfaToken")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	databasePath = db.path
	/*
	   t.Logf("%v", db.path)
	   for _, u := range db.Users {
	           for _, n := range u.Names {
	                   t.Logf("user %s, name: %v", u.Username, n)
	           }
	           for _, p := range u.Passwords {
	                   t.Logf("user %s, password: %v", u.Username, p)
	           }
	   }
	*/

	testcases := []struct {
		name          string
		operation     string
		req           *requests.Request
		overwritePath string
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name:      "add disabled totp app token with sha1",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app 30",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3be02ddd2c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
					Disabled:  true,
				},
			},
			want: map[string]interface{}{
				"token_count": 0,
			},
		},
		{
			name:      "add totp app token with sha1",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
			want: map[string]interface{}{
				"token_count": 1,
			},
		},
		{
			name:      "remove all mfa tokens",
			operation: "delete",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{},
			},
			want: map[string]interface{}{
				"token_count": 0,
			},
		},
		{
			name:      "readd totp app token with sha1",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
			want: map[string]interface{}{
				"token_count": 1,
			},
		},
		{
			name:      "delete non-existing mfa token",
			operation: "delete",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					ID: "foobar",
				},
			},
			shouldErr: true,
			err:       errors.ErrDeleteMfaToken.WithArgs("foobar", "not found"),
		},
		{
			name:      "add token with non-existing username",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: "foobar",
					Email:    "foobar@barfoo",
				},
			},
			shouldErr: true,
			err:       errors.ErrAddMfaToken.WithArgs(errors.ErrDatabaseUserNotFound),
		},
		{
			name:      "add token with duplicate secret",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "c71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
			shouldErr: true,
			err:       errors.ErrAddMfaToken.WithArgs(errors.ErrDuplicateMfaTokenSecret),
		},
		{
			name:      "add token with duplicate comment",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app",
					Type:      "totp",
					Secret:    "d71ca4c68bc14ec5b4ab8d3c3b63802c1",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
			shouldErr: true,
			err:       errors.ErrAddMfaToken.WithArgs(errors.ErrDuplicateMfaTokenComment),
		},

		{
			name:      "get tokens with mismatch user and email",
			operation: "get",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail2,
				},
			},
			shouldErr: true,
			err:       errors.ErrGetMfaTokens.WithArgs(errors.ErrDatabaseInvalidUser),
		},

		{
			name:      "delete mfa token with mismatch user and email",
			operation: "delete",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail2,
				},
				MfaToken: requests.MfaToken{
					ID: "foobar",
				},
			},
			shouldErr: true,
			err:       errors.ErrDeleteMfaToken.WithArgs("foobar", errors.ErrDatabaseInvalidUser),
		},
		{
			name:      "fail to commit when adding mfa token",
			operation: "add",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					Comment:   "ms auth app 20",
					Type:      "totp",
					Secret:    "dd71ca4c68bc14ec5b4ab8d3c3b63802c",
					Algorithm: "sha1",
					Period:    30,
					Digits:    6,
				},
			},
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrAddMfaToken.WithArgs(
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
		{
			name:      "fail to commit when deleting mfa token",
			operation: "delete",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
				MfaToken: requests.MfaToken{
					ID: "zzzzzzzzzzzzzzzzzzzzzzzzzz5h3s765Tpx5Laa",
				},
			},
			overwritePath: path.Dir(databasePath),
			shouldErr:     true,
			err: errors.ErrDeleteMfaToken.WithArgs("zzzzzzzzzzzzzzzzzzzzzzzzzz5h3s765Tpx5Laa",
				errors.ErrDatabaseCommit.WithArgs(path.Dir(databasePath), "open "+path.Dir(databasePath)+": is a directory"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			db.path = databasePath
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			switch tc.operation {
			case "add":
				if tc.overwritePath != "" {
					db.path = tc.overwritePath
				}
				if tc.req.MfaToken.Type == "totp" && tc.req.MfaToken.Passcode == "" {
					if err := generateTestPasscode(tc.req, true); err != nil {
						t.Fatalf("unexpected failure during passcode generation: %v", err)
					}
				}
				err = db.AddMfaToken(tc.req)
				if tests.EvalErrWithLog(t, err, "add mfa token", tc.shouldErr, tc.err, msgs) {
					return
				}
			case "get":
			case "delete":
				if tc.overwritePath != "" {
					db.path = tc.overwritePath
				}
				err = db.GetMfaTokens(tc.req)
				if tc.req.MfaToken.ID != "" {
					// Delete specific key.
					if tc.req.MfaToken.ID == "zzzzzzzzzzzzzzzzzzzzzzzzzz5h3s765Tpx5Laa" {
						user, err := db.getUser(tc.req.User.Username)
						if err != nil {
							t.Fatal(err)
						}
						token := user.MfaTokens[0]
						token.ID = tc.req.MfaToken.ID
					}
					err = db.DeleteMfaToken(tc.req)
					if tests.EvalErrWithLog(t, err, "delete mfa token by id", tc.shouldErr, tc.err, msgs) {
						return
					}
					break
				}
				// Delete all keys.
				bundle := tc.req.Response.Payload.(*MfaTokenBundle)
				var arr []string
				for _, k := range bundle.Get() {
					arr = append(arr, k.ID)
				}
				for _, k := range arr {
					tc.req.MfaToken.ID = k
					err = db.DeleteMfaToken(tc.req)
					if tests.EvalErrWithLog(t, err, "delete mfa token", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			case "":
				t.Fatal("empty test operation")
			default:
				t.Fatalf("unsupported test operation: %s", tc.operation)
			}

			err = db.GetMfaTokens(tc.req)
			if tests.EvalErrWithLog(t, err, "get mfa tokens", tc.shouldErr, tc.err, msgs) {
				return
			}
			bundle := tc.req.Response.Payload.(*MfaTokenBundle)
			got := make(map[string]interface{})
			got["token_count"] = bundle.Size()
			tests.EvalObjectsWithLog(t, "output", tc.want, got, msgs)
		})
	}
}

func TestDatabaseGetUsers(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabaseGetUsers")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	ts := time.Now()
	databasePath = db.path
	testcases := []struct {
		name          string
		operation     string
		req           *requests.Request
		overwritePath string
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name: "get users",
			req: &requests.Request{
				User: requests.User{
					Username: testUser1,
					Email:    testEmail1,
				},
			},
			want: map[string]interface{}{
				"user_count": 2,
				"users": []*UserMetadata{
					{
						ID:           "000000000000000000000000000000000001",
						Username:     "jsmith",
						Name:         "Smith, John",
						Email:        "jsmith@gmail.com",
						LastModified: ts,
						Created:      ts,
					},
					{
						ID:           "000000000000000000000000000000000002",
						Username:     "bjones",
						Email:        "bjones@gmail.com",
						LastModified: ts,
						Created:      ts,
					},
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			db.path = databasePath
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))

			err = db.GetUsers(tc.req)
			if tests.EvalErrWithLog(t, err, "get users", tc.shouldErr, tc.err, msgs) {
				return
			}
			bundle := tc.req.Response.Payload.(*UserMetadataBundle)
			got := make(map[string]interface{})
			got["user_count"] = bundle.Size()
			users := bundle.Get()
			for i, user := range users {
				user.ID = fmt.Sprintf("%036d", i+1)
				user.LastModified = ts
				user.Created = ts
			}
			got["users"] = bundle.Get()
			tests.EvalObjectsWithLog(t, "output", tc.want, got, msgs)
		})
	}
}

func TestDatabasePolicy(t *testing.T) {
	var databasePath string
	db, err := createTestDatabase("TestDatabasePolicy")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	databasePath = db.path
	testcases := []struct {
		name          string
		operation     string
		req           *requests.Request
		overwritePath string
		want          map[string]interface{}
		shouldErr     bool
		err           error
	}{
		{
			name: "get username and password policies",
			want: map[string]interface{}{
				"username_policy": UserPolicy{
					MinLength:            3,
					MaxLength:            50,
					AllowNonAlphaNumeric: false,
					AllowUppercase:       false,
				},
				"password_policy": PasswordPolicy{
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
				"username_policy_summary": "A username should be 3-50 character long string with lowercase, alpha-numeric characters",
				"username_policy_regex":   "^[a-z][a-z0-9]{2,49}$",
				"password_policy_summary": "A password should be 8-128 character long string",
				"password_policy_regex":   "^.{8,128}$",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			db.path = databasePath
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("database path: %s", db.path))
			got := make(map[string]interface{})
			got["username_policy"] = db.Policy.User
			got["password_policy"] = db.Policy.Password
			got["username_policy_regex"] = db.GetUsernamePolicyRegex()
			got["password_policy_regex"] = db.GetPasswordPolicyRegex()
			got["username_policy_summary"] = db.GetUsernamePolicySummary()
			got["password_policy_summary"] = db.GetPasswordPolicySummary()
			tests.EvalObjectsWithLog(t, "output", tc.want, got, msgs)
		})
	}
}
