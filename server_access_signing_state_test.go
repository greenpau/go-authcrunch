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

package authcrunch

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestServerLegacyAccessPersistenceBindingUnchanged(t *testing.T) {
	config := &Config{AuthorizationPolicies: []*authz.PolicyConfig{{Name: "legacy"}}, State: &state.Config{Directory: filepath.Join(t.TempDir(), "state")}}
	store, err := state.Open(config.State)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := *config
	snapshot.State = nil
	snapshot.Logging = nil
	oldBinding, err := state.Binding(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.OpenRecord("runtime-configuration", oldBinding)
	if err != nil {
		t.Fatal(err)
	}
	epoch := bytes.Repeat([]byte{7}, 32)
	if err := record.Save(epoch); err != nil {
		t.Fatal(err)
	}
	root := &Server{state: store}
	binding, err := root.persistentStateBinding(config)
	if err != nil || binding != hex.EncodeToString(epoch) {
		t.Fatal("legacy root epoch changed without an access profile")
	}
}
