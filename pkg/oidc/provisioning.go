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

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

const oidcGeneratedSigningKeyBits = 3072

// GenerateClientID returns a URL-safe identifier from 32 cryptographically
// random bytes. Persist it with the registration so reloads retain its identity.
func GenerateClientID() string {
	return oidcRandom()
}

// GenerateClientSecret returns a URL-safe secret from 32 cryptographically
// random bytes. Store it securely and share it only with its confidential client.
func GenerateClientSecret() string {
	return oidcRandom()
}

// NewClientConfig provisions a validated copy of config, generating a missing
// client ID and, for confidential clients, a missing secret. Existing credentials
// are preserved. Only RedirectURIs is required; name, scopes and authentication
// method receive their usual validation defaults. Set TokenEndpointAuthMethod
// to "none" to provision a public client without a secret.
//
// Provisioned clients always require S256 PKCE and retain config's consent policy.
// A confidential client that needs compatibility without PKCE can explicitly
// clear RequirePKCE on the result before AddClient. Persist the result before
// starting the provider; calling this with missing credentials on every reload
// would create new credentials. Validate and NewProvider never generate them.
func NewClientConfig(config ClientConfig) (*ClientConfig, error) {
	client := cloneClientConfig(config)
	if client.ClientID == "" {
		client.ClientID = GenerateClientID()
	}
	if client.ClientSecret == "" && (client.TokenEndpointAuthMethod == "" || client.TokenEndpointAuthMethod == "client_secret_basic" || client.TokenEndpointAuthMethod == "client_secret_post") {
		client.ClientSecret = GenerateClientSecret()
	}
	client.RequirePKCE = true
	if err := client.Validate(); err != nil {
		return nil, err
	}
	return client, nil
}

// AddClient validates and appends an independent copy of client, rejecting a
// duplicate ID without changing existing registrations. It preserves credentials
// and does not generate missing ones. Use NewClientConfig for initial provisioning.
// Configure clients before NewProvider; this method does not update a running
// provider and must not run concurrently with other accesses to this Config.
func (c *Config) AddClient(client *ClientConfig) error {
	if c == nil {
		return fmt.Errorf("oidc config is nil")
	}
	if client == nil {
		return fmt.Errorf("oidc client is nil")
	}
	candidate := cloneClientConfig(*client)
	if err := candidate.Validate(); err != nil {
		return err
	}
	for _, existing := range c.Clients {
		if existing == nil {
			return fmt.Errorf("oidc client is nil")
		}
		if existing.ClientID == candidate.ClientID {
			return fmt.Errorf("duplicate oidc client_id")
		}
	}
	c.Clients = append(c.Clients, candidate)
	return nil
}

func cloneClientConfig(config ClientConfig) *ClientConfig {
	config.RedirectURIs = slices.Clone(config.RedirectURIs)
	config.Scopes = slices.Clone(config.Scopes)
	config.RequestObjectKeys = slices.Clone(config.RequestObjectKeys)
	return &config
}

// GenerateSigningKey returns a dedicated 3072-bit RSA private key encoded as
// unencrypted PKCS#8 PEM. The caller owns secure persistence, for example in an
// embedding application's credential store. It is a provider signing key, not
// a client credential, and must not also sign the host's ordinary access tokens.
func GenerateSigningKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, oidcGeneratedSigningKeyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot generate oidc signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cannot encode oidc signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// GenerateSigningKeyFile provisions a new signing key with owner-only file
// permissions (0600 before umask). It publishes a complete file using a hard link
// and never replaces an existing path, including a symlink. The parent directory
// must already exist, be trusted, and support hard links. Concurrent provisioning
// attempts have at most one winner; errors.Is(err, fs.ErrExist) identifies losers.
// Add the successful filename to Config.SigningKeyFiles and retain it on reload.
func GenerateSigningKeyFile(filename string) error {
	key, err := GenerateSigningKey()
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(filename), ".oidc-signing-*")
	if err != nil {
		return fmt.Errorf("cannot create oidc signing key: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("cannot write oidc signing key: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot sync oidc signing key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close oidc signing key: %w", err)
	}
	if err := os.Link(file.Name(), filename); err != nil {
		return fmt.Errorf("cannot publish oidc signing key: %w", err)
	}
	return nil
}
