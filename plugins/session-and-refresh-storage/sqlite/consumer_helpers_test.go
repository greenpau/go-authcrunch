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

package sqlite_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	storage "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite/parser"
	"go.uber.org/zap"
)

// These fixtures also compile and run outside AuthCrunch's internal boundary.
func privateDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func storageConfig(t *testing.T, path string) *storage.Config {
	t.Helper()
	config, err := parser.NewSQLiteRefreshStorageConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"path", path}), "max sessions 1", "max rotations 16", "timeout 500ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The public serialized configuration is sufficient to construct a runtime.
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored storage.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	return &restored
}

type databaseIdentity struct{ db *identity.Database }

func (d databaseIdentity) WithIdentity(ctx context.Context, p tokenrefresh.Principal, apply func(map[string]any) error) error {
	if p.Backend != "local" || p.Realm != "local" || len(p.Methods) != 1 || p.Methods[0] != "pwd" {
		return tokenrefresh.ErrDenied
	}
	proof := requests.AuthenticationEvidence{UserID: p.UserID, BackendVersion: p.BackendVersion, CredentialVersion: p.CredentialVersion, Method: "pwd"}
	err := d.db.WithRefreshIdentity(ctx, proof, func(current identity.RefreshIdentity) error {
		if current.Username != p.Subject || len(current.Challenges) != 1 || current.Challenges[0] != "password" || current.AuthChallengePolicy {
			return tokenrefresh.ErrDenied
		}
		return apply(map[string]any{"sub": current.Username, "email": current.Email, "name": current.Name, "roles": current.Roles, "aud": []string{"api"}})
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		return tokenrefresh.ErrDenied
	}
	return err
}

type fixtureSigner struct {
	readerContext context.Context
	keys          *kms.CryptoKeyStore
	fail          atomic.Bool
	blockCommit   atomic.Bool
	waitCancel    atomic.Bool
	signing       chan struct{}
	canceled      chan struct{}
	reader        *sql.DB
	blocked       chan *sql.Tx
	calls         atomic.Int32
}

func (s *fixtureSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return "", tokenrefresh.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	u, err := user.NewUser(claims)
	if err != nil {
		return "", err
	}
	if err := s.keys.SignToken(nil, nil, u); err != nil {
		return "", err
	}
	clear(claims)
	maps.Copy(claims, u.AsMap())
	if s.waitCancel.Swap(false) {
		s.signing <- struct{}{}
		<-ctx.Done()
		s.canceled <- struct{}{}
		return "", ctx.Err()
	}
	if s.blockCommit.Swap(false) {
		// This reader permits BEGIN IMMEDIATE but prevents the later exclusive
		// commit lock, exercising an actual SQLite commit failure after signing.
		tx, err := s.reader.BeginTx(s.readerContext, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return "", err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&count); err != nil {
			_ = tx.Rollback()
			return "", err
		}
		s.blocked <- tx
	}
	return u.Token, nil
}

func newFixtureSigner(t *testing.T) (*fixtureSigner, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDirectory(t)
	privatePath, publicPath := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	for path, data := range map[string][]byte{
		privatePath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		publicPath:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := kms.NewCryptoKeyStoreConfig([]string{cfgutil.EncodeArgs([]string{"crypto", "key", "fixture", "sign-verify", "from", "file", privatePath})})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kms.NewCryptoKeyStore(config, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureSigner{readerContext: t.Context(), keys: keys, blocked: make(chan *sql.Tx, 1), signing: make(chan struct{}, 1), canceled: make(chan struct{}, 1)}, pub, publicPath
}

// This storage consumer receives server-held evidence from completed provider
// authentication. Portal callback admission is exercised in authn's TLS suite.
// It never accepts a principal or claims document from an HTTP caller.
type capturedProviderIdentity struct{}

func (capturedProviderIdentity) WithIdentity(ctx context.Context, p tokenrefresh.Principal, apply func(map[string]any) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Source != tokenrefresh.ProviderSnapshotSource || p.Backend != "upstream" || p.Realm != "upstream" || p.BackendKind != "oauth" || len(p.ProviderSnapshot) > tokenrefresh.MaxProviderSnapshotSize {
		return tokenrefresh.ErrDenied
	}
	var claims map[string]any
	if json.Unmarshal(p.ProviderSnapshot, &claims) != nil || claims["sub"] != p.Subject {
		return tokenrefresh.ErrDenied
	}
	return apply(claims)
}
