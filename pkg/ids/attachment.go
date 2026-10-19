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

package ids

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
)

// BindIdentityAttachment resolves an optional backend attachment against the
// host's configured stores. Only the concrete local store is a valid target.
// Call before serving requests; omission retains the provider's private memory.
func BindIdentityAttachment(backend any, stores []IdentityStore) error {
	consumer, ok := backend.(attachment.Consumer)
	if !ok {
		return nil
	}
	a := consumer.IdentityAttachment()
	if a == nil {
		return fmt.Errorf("missing identity attachment")
	}
	if a.StoreName() == "" {
		return nil
	}
	var selected *local.IdentityStore
	for _, store := range stores {
		if store.GetName() != a.StoreName() {
			continue
		}
		candidate, ok := store.(*local.IdentityStore)
		if !ok || !candidate.Configured() || selected != nil {
			return fmt.Errorf("attached identity store must be a unique configured local store")
		}
		selected = candidate
	}
	if selected == nil {
		return fmt.Errorf("attached local identity store not found")
	}
	return attachment.BindStore(a, selected)
}
