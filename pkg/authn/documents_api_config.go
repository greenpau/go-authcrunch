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
	"fmt"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

// DocumentsAPIConfig configures Documents independently of Admin and Profile.
// Its zero value disables the API. Apply it with ConfigureDocumentsAPI before
// constructing a portal; only an explicit Enabled value permits provisioning.
type DocumentsAPIConfig struct {
	Enabled bool              `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Storage *documents.Config `json:"storage,omitempty" xml:"storage,omitempty" yaml:"storage,omitempty"`
}

// ConfigureDocumentsAPI installs a snapshot, preserving the other API settings.
// A zero-value config disables Documents without opening or validating storage.
// Nil and invalid enabled configurations return an error without changing cfg.
func (cfg *PortalConfig) ConfigureDocumentsAPI(settings *DocumentsAPIConfig) error {
	if cfg == nil {
		return fmt.Errorf("portal config is nil")
	}
	if settings == nil {
		return fmt.Errorf("documents API config is nil")
	}
	var storage *documents.Config
	if settings.Storage != nil {
		copy := *settings.Storage
		copy.Realms = slices.Clone(copy.Realms)
		storage = &copy
	}
	if settings.Enabled {
		if err := storage.Validate(); err != nil {
			return err
		}
	}
	api := APIConfig{}
	if cfg.API != nil {
		api = *cfg.API
	}
	api.DocumentsEnabled = settings.Enabled
	cfg.API, cfg.Documents = &api, storage
	return nil
}
