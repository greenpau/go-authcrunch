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

package authcrunch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/sso"
	"go.uber.org/zap"
)

func TestE2EServerRejectsMalformedSSOKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	databasePath := filepath.Join(dir, "users.json")
	if _, err := identity.NewDatabase(databasePath); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(dir, "certificate.pem")
	if err := os.WriteFile(certificatePath, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	config := &authcrunch.Config{
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": databasePath}}},
		SingleSignOnProviders: []*sso.SingleSignOnProviderConfig{{
			Name: "broken", Driver: "aws", EntityID: "urn:authcrunch:test", Locations: []string{"https://example.test/sso"},
			CertPath: certificatePath, PrivateKeyPath: "testdata/sso/authp_saml.key",
		}},
		AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, SingleSignOnProviders: []string{"broken"}}},
	}
	runtime, err := authcrunch.NewServer(config, zap.NewNop())
	if runtime != nil || err == nil || !strings.Contains(err.Error(), "certificate PEM block not found") {
		t.Fatalf("runtime = %T, error = %v", runtime, err)
	}
}
