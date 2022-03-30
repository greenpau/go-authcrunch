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

package testutils

import (
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"path/filepath"
)

// CreateTestDatabase returns database instance.
func CreateTestDatabase(s string) (*identity.Database, error) {
	tmpDir, err := tests.TempDir(s)
	if err != nil {
		return nil, err
	}
	reqs := []*requests.Request{
		{
			User: requests.User{
				Username: tests.TestUser1,
				Password: tests.TestPwd1,
				Email:    tests.TestEmail1,
				FullName: tests.TestFullName1,
				Roles:    tests.TestRoles1,
			},
		},
		{
			User: requests.User{
				Username: tests.TestUser2,
				Password: tests.TestPwd2,
				Email:    tests.TestEmail2,
				FullName: tests.TestFullName2,
				Roles:    tests.TestRoles2,
			},
		},
	}

	db, err := identity.NewDatabase(filepath.Join(tmpDir, "user_db.json"))
	if err != nil {
		return nil, err
	}

	for _, req := range reqs {
		if err := db.AddUser(req); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// CreateEmptyTestDatabase returns empty database instance.
func CreateEmptyTestDatabase(s string) (*identity.Database, error) {
	tmpDir, err := tests.TempDir(s)
	if err != nil {
		return nil, err
	}
	return identity.NewDatabase(filepath.Join(tmpDir, "user_db.json"))
}
