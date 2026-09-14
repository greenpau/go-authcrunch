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
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

func TestLocalRegistryRuntimeOwnership(t *testing.T) {
	cfg := &LocalUserRegistryProvider{Name: "registry", Dropbox: filepath.Join(t.TempDir(), "registrations.json"), EmailProviderName: "unused", AdminEmails: []string{"admin@example.test"}, IdentityStoreName: "local", RealmName: "local"}
	first, err := cfg.NewRuntime(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := cfg.NewRuntime(zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if cfg.cache != nil || cfg.db != nil {
		t.Fatal("configuration acquired runtime state")
	}
	first.AdminEmails[0] = "changed@example.test"
	if second.AdminEmails[0] != cfg.AdminEmails[0] {
		t.Fatal("runtime copied mutable settings by reference")
	}
	id := strings.Repeat("a", 40)
	entry := map[string]string{"username": "alice", "password": "synthetic", "email": "alice@example.test"}
	if err := first.AddRegistrationEntry(id, entry); err != nil {
		t.Fatal(err)
	}
	if err := first.Activate(zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.GetRegistrationEntry(id); err != nil {
		t.Fatal("repeated activation discarded live state")
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(second.Close)
	}
	wg.Wait()
	select {
	case <-second.cache.done:
	default:
		t.Fatal("registry worker survived Close")
	}
	if _, err := first.GetRegistrationEntry(id); err != nil {
		t.Fatal("closing replacement affected active registry")
	}
	first.Close()
	if _, err := first.GetRegistrationEntry(id); err == nil {
		t.Fatal("disposed registry retained registration")
	}
	if err := first.Activate(zap.NewNop()); err == nil {
		t.Fatal("disposed registry restarted")
	}
	if _, err := cfg.NewRuntime(nil); err == nil {
		t.Fatal("nil logger accepted")
	}
	if _, err := (*LocalUserRegistryProvider)(nil).NewRuntime(zap.NewNop()); err == nil {
		t.Fatal("nil configuration accepted")
	}
	(*LocalUserRegistryProvider)(nil).Close()
}
