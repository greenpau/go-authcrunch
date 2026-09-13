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

package oidc_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestOIDCGeneratedCredentials(t *testing.T) {
	seen := make(map[string]bool)
	for range 128 {
		for _, value := range []string{oidc.GenerateClientID(), oidc.GenerateClientSecret()} {
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(decoded) != 32 || seen[value] {
				t.Fatal("generated credential is malformed or repeated")
			}
			seen[value] = true
		}
	}
}

func TestOIDCNewClientConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*oidc.ClientConfig)
		err    string
	}{
		{name: "defaults"},
		{name: "preserved credentials", modify: func(c *oidc.ClientConfig) {
			c.ClientID, c.ClientName, c.ClientSecret = "app", "Application", strings.Repeat("s", 32)
			c.Scopes, c.SkipConsent = []string{"openid"}, true
		}},
		{name: "preserved identifier", modify: func(c *oidc.ClientConfig) { c.ClientID = "app" }},
		{name: "preserved secret", modify: func(c *oidc.ClientConfig) { c.ClientSecret = strings.Repeat("s", 32) }},
		{name: "post", modify: func(c *oidc.ClientConfig) { c.TokenEndpointAuthMethod = "client_secret_post" }},
		{name: "public", modify: func(c *oidc.ClientConfig) { c.TokenEndpointAuthMethod = "none" }},
		{name: "public loopback", modify: func(c *oidc.ClientConfig) {
			c.TokenEndpointAuthMethod, c.RedirectURIs = "none", []string{"http://127.0.0.1:8400/callback"}
		}},
		{name: "missing redirect", modify: func(c *oidc.ClientConfig) { c.RedirectURIs = nil }, err: "oidc requires distinct redirect_uris"},
		{name: "duplicate redirect", modify: func(c *oidc.ClientConfig) { c.RedirectURIs = append(c.RedirectURIs, c.RedirectURIs[0]) }, err: "oidc requires distinct redirect_uris"},
		{name: "HTTP redirect", modify: func(c *oidc.ClientConfig) { c.RedirectURIs = []string{"http://app.example.test/callback"} }, err: "oidc redirect_uri requires HTTPS or a public client's literal loopback address"},
		{name: "invalid ID", modify: func(c *oidc.ClientConfig) { c.ClientID = " app" }, err: "invalid oidc client_id"},
		{name: "long name", modify: func(c *oidc.ClientConfig) { c.ClientName = strings.Repeat("a", 257) }, err: "oidc client_name is too long"},
		{name: "short secret", modify: func(c *oidc.ClientConfig) { c.ClientSecret = "short" }, err: "oidc client secrets require 32 to 1024 bytes"},
		{name: "unsupported auth", modify: func(c *oidc.ClientConfig) { c.TokenEndpointAuthMethod = "private_key_jwt" }, err: "unsupported oidc token endpoint authentication method"},
		{name: "public secret", modify: func(c *oidc.ClientConfig) {
			c.TokenEndpointAuthMethod, c.ClientSecret = "none", strings.Repeat("s", 32)
		}, err: "public oidc clients cannot have a secret"},
		{name: "missing openid scope", modify: func(c *oidc.ClientConfig) { c.Scopes = []string{"email"} }, err: "oidc scopes must be distinct and include openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := oidc.ClientConfig{RedirectURIs: []string{"https://app.example.test/callback"}}
			if tc.modify != nil {
				tc.modify(&input)
			}
			before, _ := json.Marshal(input)
			client, err := oidc.NewClientConfig(input)
			after, _ := json.Marshal(input)
			if !bytes.Equal(before, after) {
				t.Fatal("constructor changed caller configuration")
			}
			if tc.err != "" {
				if err == nil || err.Error() != tc.err || client != nil {
					t.Fatal("invalid registration was not rejected as expected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.ClientID == "" || !client.RequirePKCE || client.SkipConsent != input.SkipConsent {
				t.Fatal("provisioning defaults missing or consent policy changed")
			}
			if (input.ClientID != "" && client.ClientID != input.ClientID) || (input.ClientSecret != "" && client.ClientSecret != input.ClientSecret) || (input.ClientName != "" && client.ClientName != input.ClientName) {
				t.Fatal("explicit credentials or name changed")
			}
			if input.ClientName == "" && client.ClientName != client.ClientID {
				t.Fatal("default name does not match client ID")
			}
			method := input.TokenEndpointAuthMethod
			if method == "" {
				method = "client_secret_basic"
			}
			if client.TokenEndpointAuthMethod != method || (method == "none" && client.ClientSecret != "") || (method != "none" && len(client.ClientSecret) < 32) {
				t.Fatal("incorrect client authentication defaults")
			}
			scopes := input.Scopes
			if len(scopes) == 0 {
				scopes = []string{"openid", "profile", "email"}
			}
			if !slices.Equal(client.Scopes, scopes) || !slices.Equal(client.RedirectURIs, input.RedirectURIs) {
				t.Fatal("incorrect scopes or callback")
			}
			client.RedirectURIs[0], client.Scopes[0] = "https://changed.example.test/callback", "changed"
			after, _ = json.Marshal(input)
			if !bytes.Equal(before, after) {
				t.Fatal("constructor retained caller-owned slices")
			}
		})
	}
}

func TestOIDCAddClient(t *testing.T) {
	input := &oidc.ClientConfig{ClientID: "app", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://app.example.test/callback"}, Scopes: []string{"openid"}}
	var config oidc.Config
	if err := config.AddClient(input); err != nil {
		t.Fatal(err)
	}
	if input.ClientName != "" || input.TokenEndpointAuthMethod != "" || config.Clients[0].ClientName != "app" || config.Clients[0].RequirePKCE {
		t.Fatal("AddClient modified the caller or changed explicit PKCE policy")
	}
	input.ClientSecret, input.RedirectURIs[0], input.Scopes[0] = "changed", "https://changed.example.test/callback", "changed"
	if config.Clients[0].ClientSecret != strings.Repeat("s", 32) || config.Clients[0].RedirectURIs[0] != "https://app.example.test/callback" || config.Clients[0].Scopes[0] != "openid" {
		t.Fatal("AddClient retained caller-owned registration")
	}
	for _, tc := range []struct {
		name   string
		config *oidc.Config
		client *oidc.ClientConfig
		err    string
	}{
		{"nil config", nil, config.Clients[0], "oidc config is nil"},
		{"nil client", &config, nil, "oidc client is nil"},
		{"duplicate", &config, config.Clients[0], "duplicate oidc client_id"},
		{"invalid existing entry", &oidc.Config{Clients: []*oidc.ClientConfig{nil}}, config.Clients[0], "oidc client is nil"},
		{"missing ID", &config, &oidc.ClientConfig{}, "invalid oidc client_id"},
		{"missing secret", &config, &oidc.ClientConfig{ClientID: "new"}, "oidc client secrets require 32 to 1024 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := json.Marshal(tc.config)
			err := tc.config.AddClient(tc.client)
			after, _ := json.Marshal(tc.config)
			if err == nil || err.Error() != tc.err || !bytes.Equal(before, after) {
				t.Fatal("failed AddClient did not preserve configuration or return expected error")
			}
		})
	}
	second, err := oidc.NewClientConfig(oidc.ClientConfig{TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://public.example.test/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := config.AddClient(second); err != nil || len(config.Clients) != 2 || config.Clients[1].ClientID != second.ClientID {
		t.Fatal("could not append independent public client")
	}
}

func parseProvisionedKey(t *testing.T, data []byte) *rsa.PrivateKey {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("generated key is not one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("generated private key cannot be parsed")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != 3072 || key.Validate() != nil {
		t.Fatal("generated key is not a valid 3072-bit RSA key")
	}
	return key
}

func TestOIDCGenerateSigningKey(t *testing.T) {
	first, err := oidc.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := oidc.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	a, b := parseProvisionedKey(t, first), parseProvisionedKey(t, second)
	if a.N.Cmp(b.N) == 0 {
		t.Fatal("generated keys are identical")
	}
}

func TestOIDCGenerateSigningKeyFile(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "signing.pem")
	if err := oidc.GenerateSigningKeyFile(filename); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	parseProvisionedKey(t, original)
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions are not 0600")
	}
	for _, tc := range []struct {
		name  string
		path  string
		setup func(string) error
		want  error
	}{
		{"existing file", filename, nil, fs.ErrExist},
		{"directory", filepath.Join(dir, "directory"), func(path string) error { return os.Mkdir(path, 0700) }, fs.ErrExist},
		{"symlink", filepath.Join(dir, "symlink"), func(path string) error { return os.Symlink(filename, path) }, fs.ErrExist},
		{"dangling symlink", filepath.Join(dir, "dangling"), func(path string) error { return os.Symlink(filepath.Join(dir, "absent"), path) }, fs.ErrExist},
		{"missing parent", filepath.Join(dir, "missing", "key.pem"), nil, fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				if err := tc.setup(tc.path); err != nil {
					t.Fatal(err)
				}
			}
			if err := oidc.GenerateSigningKeyFile(tc.path); !errors.Is(err, tc.want) {
				t.Fatalf("unexpected key provisioning failure: %v", err)
			}
			current, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(current, original) {
				t.Fatal("failed provisioning changed original key")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("provisioning followed a dangling symlink")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".oidc-signing-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("provisioning left temporary private keys")
	}
}

func TestOIDCConcurrentSigningKeyProvisioning(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "signing.pem")
	var results [2]error
	var group sync.WaitGroup
	for i := range results {
		group.Go(func() { results[i] = oidc.GenerateSigningKeyFile(filename) })
	}
	group.Wait()
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, fs.ErrExist) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent provisioning did not have exactly one winner")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	parseProvisionedKey(t, data)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("concurrent provisioning left temporary files")
	}
}
