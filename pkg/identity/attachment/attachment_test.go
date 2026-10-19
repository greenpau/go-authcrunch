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

package attachment_test

import (
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAttachmentBinding(t *testing.T) {
	explicit, err := attachment.New(attachment.Config{LocalIdentityStore: "localdb"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := explicit.Store(); err == nil {
		t.Fatal("unbound explicit attachment fell back to memory")
	}
	var missing *identity.Database
	if err := attachment.BindStore(explicit, missing); err == nil {
		t.Fatal("typed nil store bound")
	}
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := attachment.BindStore(explicit, db); err != nil {
			t.Fatal("idempotent binding failed", err)
		}
	}
	other, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.BindStore(explicit, other); err == nil {
		t.Fatal("attachment authority replaced")
	}
	implicit, err := attachment.New(attachment.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.BindStore(implicit, db); err == nil {
		t.Fatal("implicit attachment accepted named authority")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			store, err := implicit.Store()
			if err != nil {
				t.Error(err)
				return
			}
			memory, ok := store.(*identity.Database)
			if !ok || len(memory.Users) != 0 {
				t.Error("implicit store generated an administrator")
			}
		})
	}
	wg.Wait()
}

func TestAttachmentVerifiedIdentity(t *testing.T) {
	a, err := attachment.New(attachment.Config{})
	if err != nil {
		t.Fatal(err)
	}
	verified := requests.NewRequest()
	verified.ExternalIdentity = requests.ExternalIdentity{Issuer: "https://issuer.test", Subject: "opaque-subject"}
	verified.Response.Payload = map[string]any{"email": "same@example.test", "name": "Member"}
	if err := a.Authenticate(t.Context(), verified, "provider", "oauth"); err != nil {
		t.Fatal(err)
	}
	first := verified.ExternalIdentity.Evidence.UserID
	if first == "" {
		t.Fatal("no local evidence")
	}
	if err := a.Authenticate(t.Context(), verified, "provider", "oauth"); err != nil || first != verified.ExternalIdentity.Evidence.UserID {
		t.Fatal("repeat authentication changed identity", err)
	}
	b, err := attachment.New(attachment.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Authenticate(t.Context(), verified, "provider", "oauth"); err != nil || first == verified.ExternalIdentity.Evidence.UserID {
		t.Fatal("private memory databases shared identities", err)
	}
	verified.ExternalIdentity.Subject = ""
	if err := a.Authenticate(t.Context(), verified, "provider", "oauth"); err == nil || verified.ExternalIdentity.Evidence.UserID != "" {
		t.Fatal("failed authentication retained prior evidence")
	}
	missing := requests.NewRequest()
	if err := a.Authenticate(t.Context(), missing, "provider", "oauth"); err == nil {
		t.Fatal("unverified empty identity accepted")
	}
}

func TestAttachmentBindingPointerIdentity(t *testing.T) {
	// A concrete store may contain non-comparable fields. Only its pointer
	// identity determines whether binding the same authority is idempotent.
	type storeWithSlice struct {
		attachment.Store
		values []string
	}
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store := &storeWithSlice{Store: db, values: []string{"fixture"}}
	if err := attachment.BindStore(nil, store); err == nil {
		t.Fatal("nil attachment accepted")
	}
	a, err := attachment.New(attachment.Config{LocalIdentityStore: "localdb"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := attachment.BindStore(a, store); err != nil {
			t.Fatal(err)
		}
	}
	copy := *store
	if err := attachment.BindStore(a, &copy); err == nil {
		t.Fatal("distinct store pointer replaced authority")
	}
}
