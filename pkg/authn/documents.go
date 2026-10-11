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

package authn

import (
	"context"
	"fmt"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

func (p *Portal) configureDocuments() error {
	if p.config.API == nil || !p.config.API.DocumentsEnabled {
		return nil
	}
	if p.config.Documents == nil {
		return documents.ErrConfig
	}
	c := *p.config.Documents
	c.Realms = slices.Clone(c.Realms)
	if err := c.Validate(); err != nil {
		return err
	}
	for _, realm := range c.Realms {
		count := 0
		for _, store := range p.identityStores {
			if store.GetRealm() != realm {
				continue
			}
			count++
			if _, ok := store.(refreshIdentityStore); !ok {
				return fmt.Errorf("documents realm lacks transactional identity verification")
			}
		}
		for _, provider := range p.identityProviders {
			if provider.GetRealm() == realm {
				count++
			}
		}
		if count != 1 || p.getIdentityStoreByRealm(realm) == nil {
			return fmt.Errorf("documents realm must identify exactly one supported identity store")
		}
	}
	store, err := documents.Open(context.Background(), c, p.config.Name)
	if err != nil {
		return fmt.Errorf("configure documents: %w", err)
	}
	p.documents, p.documentsConfig = store, &c
	return nil
}
