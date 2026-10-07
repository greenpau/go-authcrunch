// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package idp_test

import (
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"strings"
	"testing"
)

func TestLoginIdentityValidation(t *testing.T) {
	valid := func() *idp.LoginIdentity {
		return &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}}
	}
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	if (*idp.LoginIdentity)(nil).Validate() == nil {
		t.Fatal("nil identity accepted")
	}
	for _, change := range []func(*idp.LoginIdentity){func(i *idp.LoginIdentity) { i.Subject = "" }, func(i *idp.LoginIdentity) { i.Subject = "bad\n" }, func(i *idp.LoginIdentity) { i.Subject = "\xff" }, func(i *idp.LoginIdentity) { i.Name = strings.Repeat("x", 257) }, func(i *idp.LoginIdentity) { i.Email = "Name <alice@example.test>" }, func(i *idp.LoginIdentity) { i.Roles = nil }, func(i *idp.LoginIdentity) { i.Roles = []string{" "} }, func(i *idp.LoginIdentity) { i.Roles = make([]string, 33) }} {
		i := valid()
		change(i)
		if i.Validate() == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
