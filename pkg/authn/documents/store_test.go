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

package documents

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testKey(t *testing.T, userID string) Key {
	t.Helper()
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := private.PublicKey().Bytes()
	hash := sha256.Sum256(public)
	encode := base64.RawURLEncoding.EncodeToString
	return Key{UserID: userID, KeyID: encode(hash[:]), PublicKey: encode(public), Vault: &Vault{Salt: encode(make([]byte, 32)), Nonce: encode(make([]byte, 12)), Ciphertext: encode(make([]byte, 48))}}
}
func testStore(t *testing.T, alter func(*Config)) (*Store, Config, Key, Key) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := Config{Database: filepath.Join(dir, "documents.db"), PublicOrigin: "https://portal.example.test", BasePath: "/auth", Realms: []string{"local"}}
	if alter != nil {
		alter(&c)
	}
	s, err := Open(t.Context(), c, "portal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	alice, bob := testKey(t, uuid.NewString()), testKey(t, uuid.NewString())
	for _, key := range []Key{alice, bob} {
		if err := s.RegisterKey(t.Context(), key.UserID, key); err != nil {
			t.Fatal(err)
		}
	}
	return s, c, alice, bob
}
func testEnvelope(key Key) Envelope {
	return Envelope{KeyID: key.KeyID, EphemeralKey: key.PublicKey, Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48))}
}
func testManifest(key Key) Manifest {
	return Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: testEnvelope(key)}
}
func testReady(t *testing.T, s *Store, key Key) File {
	t.Helper()
	f, err := s.Allocate(t.Context(), key.UserID, 32, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutManifest(t.Context(), key.UserID, f.ID, testManifest(key)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutChunk(t.Context(), key.UserID, f.ID, 0, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(t.Context(), key.UserID, f.ID); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestStoreUploadSharingAndRestart(t *testing.T) {
	s, c, alice, bob := testStore(t, nil)
	ctx := t.Context()
	f, err := s.Allocate(ctx, alice.UserID, 32, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, alice.UserID, f.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("published incomplete upload")
	}
	if _, err := s.GetFile(ctx, bob.UserID, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("recipient observed unfinished upload")
	}
	if err := s.PutManifest(ctx, alice.UserID, f.ID, testManifest(alice)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutChunk(ctx, alice.UserID, f.ID, 0, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, alice.UserID, f.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bob)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Commit(ctx, alice.UserID, f.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.PutChunk(ctx, alice.UserID, f.ID, 0, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if err := s.PutManifest(ctx, alice.UserID, f.ID, testManifest(alice)); err != nil {
			t.Fatal(err)
		}
		if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bob)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutChunk(ctx, alice.UserID, f.ID, 0, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("replaced immutable chunk")
	}
	if err := s.Delete(ctx, bob.UserID, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("recipient deleted owner file")
	}
	if err := s.Share(ctx, bob.UserID, f.ID, uuid.NewString(), testEnvelope(alice)); !errors.Is(err, ErrNotFound) {
		t.Fatal("recipient reshared file")
	}
	got, err := s.GetFile(ctx, bob.UserID, f.ID)
	if err != nil || got.Envelope == nil || got.Envelope.KeyID != bob.KeyID || got.State != "ready" {
		t.Fatal("wrong recipient descriptor")
	}
	key, err := s.GetKey(ctx, alice.UserID, bob.UserID)
	if err != nil || key.Vault != nil {
		t.Fatal("public lookup exposed vault")
	}
	list, err := s.ListFiles(ctx, bob.UserID, "")
	if err != nil || len(list.Files) != 1 || list.Files[0].Metadata != "" || list.Files[0].Envelope != nil {
		t.Fatal("wrong recipient list")
	}
	oldID := s.PortalID()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, c, "portal")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.PortalID() != oldID {
		t.Fatal("restart changed portal identity")
	}
	if data, err := reopened.GetChunk(ctx, bob.UserID, f.ID, 0); err != nil || len(data) != 32 {
		t.Fatal("restart lost authorized content")
	}
	if err := reopened.Revoke(ctx, alice.UserID, f.ID, bob.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetChunk(ctx, bob.UserID, f.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("revocation retained access")
	}
	if err := reopened.Delete(ctx, alice.UserID, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetFile(ctx, alice.UserID, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted descriptor survived")
	}
	if _, err := Open(ctx, c, "different portal"); !errors.Is(err, ErrConfig) {
		t.Fatal("database crossed portal boundary")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.PublicOrigin = "https://other.example.test" }, func(c *Config) { c.BasePath = "/other" }} {
		changed := c
		mutate(&changed)
		if opened, err := Open(ctx, changed, "portal"); !errors.Is(err, ErrConfig) {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatal("database crossed origin or mount boundary")
		}
	}
}

func TestStoreGlobalQuotasAndRecipientKeyReplacement(t *testing.T) {
	for _, limit := range []string{"bytes", "files"} {
		t.Run(limit, func(t *testing.T) {
			s, _, alice, bob := testStore(t, func(c *Config) {
				c.MaxFileBytes, c.MaxUserBytes, c.MaxTotalBytes = 32, 64, 64
				c.MaxUserFiles, c.MaxTotalFiles = 2, 10
				if limit == "files" {
					c.MaxTotalBytes, c.MaxTotalFiles = 1024, 2
				}
			})
			a := testReady(t, s, alice)
			testReady(t, s, bob)
			if _, err := s.Allocate(t.Context(), bob.UserID, 32, 1); !errors.Is(err, ErrQuota) {
				t.Fatal("cross-user allocation escaped total quota")
			}
			if err := s.Delete(t.Context(), alice.UserID, a.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Allocate(t.Context(), bob.UserID, 32, 1); err != nil {
				t.Fatal("delete did not release quota", err)
			}
		})
	}
	s, _, alice, bob := testStore(t, func(c *Config) { c.MaxKeys = 3; c.MaxRecipients = 1 })
	ctx := t.Context()
	charlie := testKey(t, uuid.NewString())
	if err := s.RegisterKey(ctx, charlie.UserID, charlie); err != nil {
		t.Fatal(err)
	}
	extra := testKey(t, uuid.NewString())
	if err := s.RegisterKey(ctx, extra.UserID, extra); !errors.Is(err, ErrQuota) {
		t.Fatal("registration escaped quota")
	}
	if err := s.RegisterKey(ctx, alice.UserID, alice); err != nil {
		t.Fatal("quota blocked identical retry")
	}
	f := testReady(t, s, alice)
	if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bob)); err != nil {
		t.Fatal(err)
	}
	if err := s.Share(ctx, alice.UserID, f.ID, charlie.UserID, testEnvelope(charlie)); !errors.Is(err, ErrQuota) {
		t.Fatal("grant escaped recipient quota")
	}
	if err := s.ResetKey(ctx, bob.UserID, bob.KeyID); err != nil {
		t.Fatal(err)
	}
	bobReplacement := testKey(t, bob.UserID)
	if err := s.RegisterKey(ctx, bob.UserID, bobReplacement); err != nil {
		t.Fatal(err)
	}
	if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bob)); !errors.Is(err, ErrConflict) {
		t.Fatal("stale recipient fingerprint accepted")
	}
	if _, err := s.GetFile(ctx, bob.UserID, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("new key inherited old grant")
	}
	if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bobReplacement)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreConcurrentShareAndRecipientReset(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing_grant=%t", existing), func(t *testing.T) {
			s, config, alice, bob := testStore(t, func(c *Config) { c.MaxRecipients = 1 })
			other, err := Open(t.Context(), config, "portal")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			file := testReady(t, s, alice)
			if existing {
				if err := s.Share(t.Context(), alice.UserID, file.ID, bob.UserID, testEnvelope(bob)); err != nil {
					t.Fatal(err)
				}
			}
			// Independent connections must serialize the recipient-key check,
			// grant creation and reset. Neither ordering may resurrect a grant.
			start := make(chan struct{})
			shared, reset := make(chan error, 1), make(chan error, 1)
			var work sync.WaitGroup
			work.Go(func() {
				<-start
				shared <- s.Share(t.Context(), alice.UserID, file.ID, bob.UserID, testEnvelope(bob))
			})
			work.Go(func() {
				<-start
				reset <- other.ResetKey(t.Context(), bob.UserID, bob.KeyID)
			})
			close(start)
			work.Wait()
			if err := <-reset; err != nil {
				t.Fatal("concurrent reset failed", err)
			}
			if err := <-shared; err != nil && !errors.Is(err, ErrNotFound) {
				t.Fatal("share did not serialize with reset", err)
			}
			for _, store := range []*Store{s, other} {
				if _, err := store.GetKey(t.Context(), bob.UserID, bob.UserID); !errors.Is(err, ErrNotFound) {
					t.Fatal("reset retained recipient key", err)
				}
				if _, err := store.GetChunk(t.Context(), bob.UserID, file.ID, 0); !errors.Is(err, ErrNotFound) {
					t.Fatal("reset retained recipient access", err)
				}
				if recipients, err := store.Recipients(t.Context(), alice.UserID, file.ID); err != nil || len(recipients) != 0 {
					t.Fatal("share resurrected a removed recipient", err)
				}
			}
			replacement := testKey(t, bob.UserID)
			if err := other.RegisterKey(t.Context(), bob.UserID, replacement); err != nil {
				t.Fatal(err)
			}
			if err := s.Share(t.Context(), alice.UserID, file.ID, bob.UserID, testEnvelope(bob)); !errors.Is(err, ErrConflict) {
				t.Fatal("stale key could share after reset", err)
			}
			if err := s.Share(t.Context(), alice.UserID, file.ID, bob.UserID, testEnvelope(replacement)); err != nil {
				t.Fatal("fresh sharing or released recipient quota failed", err)
			}
			if chunk, err := other.GetChunk(t.Context(), bob.UserID, file.ID, 0); err != nil || !bytes.Equal(chunk, make([]byte, 32)) {
				t.Fatal("fresh recipient could not read preserved file", err)
			}
		})
	}
}

func TestStorePaginationDoesNotExposeOtherOwners(t *testing.T) {
	s, _, alice, bob := testStore(t, nil)
	ctx := t.Context()
	want := make(map[string]bool)
	for range 102 {
		f, err := s.Allocate(ctx, alice.UserID, 16, 1)
		if err != nil {
			t.Fatal(err)
		}
		want[f.ID] = true
	}
	testReady(t, s, bob)
	first, err := s.ListFiles(ctx, alice.UserID, "")
	if err != nil || len(first.Files) != 100 || first.Next != first.Files[99].ID {
		t.Fatal("first page boundary")
	}
	second, err := s.ListFiles(ctx, alice.UserID, first.Next)
	if err != nil || len(second.Files) != 2 || second.Next != "" {
		t.Fatal("second page boundary")
	}
	last := ""
	for _, f := range append(first.Files, second.Files...) {
		if !want[f.ID] || f.ID <= last || f.Owner != alice.UserID || f.Envelope != nil || f.Metadata != "" {
			t.Fatal("cursor leaked or repeated descriptor")
		}
		delete(want, f.ID)
		last = f.ID
	}
	if len(want) != 0 {
		t.Fatal("pagination lost files")
	}
}
func TestStoreQuotasExpirationAndConcurrentWriters(t *testing.T) {
	s, c, alice, _ := testStore(t, func(c *Config) {
		c.MaxFileBytes = 32
		c.MaxUserBytes = 32
		c.MaxTotalBytes = 64
		c.MaxUserFiles = 1
		c.UploadTTLSeconds = 60
	})
	other, err := Open(t.Context(), c, "portal")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*Store{s, other} {
		wg.Go(func() { _, err := store.Allocate(t.Context(), alice.UserID, 32, 1); results <- err })
	}
	wg.Wait()
	close(results)
	successes, quotas := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrQuota) {
			quotas++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || quotas != 1 {
		t.Fatal("concurrent allocation escaped quota")
	}
	list, err := s.ListFiles(t.Context(), alice.UserID, "")
	if err != nil || len(list.Files) != 1 {
		t.Fatal("allocation count")
	}
	old := list.Files[0].ID
	s.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if err := s.PutChunk(t.Context(), alice.UserID, old, 0, make([]byte, 32)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired upload resumed")
	}
	if _, err := s.Allocate(t.Context(), alice.UserID, 32, 1); err != nil {
		t.Fatal("expiration did not release quota", err)
	}
	if err := s.Delete(t.Context(), alice.UserID, old); !errors.Is(err, ErrNotFound) {
		t.Fatal("pruned file retained")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ListFiles(canceled, alice.UserID, ""); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}
func TestStoreKeyResetAndValidation(t *testing.T) {
	s, _, alice, bob := testStore(t, nil)
	ctx := t.Context()
	f := testReady(t, s, alice)
	g := testReady(t, s, bob)
	if err := s.Share(ctx, alice.UserID, f.ID, bob.UserID, testEnvelope(bob)); err != nil {
		t.Fatal(err)
	}
	if err := s.Share(ctx, bob.UserID, g.ID, alice.UserID, testEnvelope(alice)); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterKey(ctx, alice.UserID, alice); err != nil {
		t.Fatal("identical enrollment failed")
	}
	replacement := testKey(t, alice.UserID)
	if err := s.RegisterKey(ctx, alice.UserID, replacement); !errors.Is(err, ErrConflict) {
		t.Fatal("replaced enrolled key")
	}
	if err := s.ResetKey(ctx, alice.UserID, bob.KeyID); !errors.Is(err, ErrConflict) {
		t.Fatal("reset ignored confirmed key fingerprint", err)
	}
	if _, err := s.GetKey(ctx, alice.UserID, alice.UserID); err != nil {
		t.Fatal("failed reset deleted registration", err)
	}
	if err := s.ResetKey(ctx, alice.UserID, alice.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetFile(ctx, bob.UserID, f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("reset retained owned file")
	}
	if _, err := s.GetFile(ctx, alice.UserID, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("reset retained received grant")
	}
	if _, err := s.GetFile(ctx, bob.UserID, g.ID); err != nil {
		t.Fatal("reset deleted another owner's file")
	}
	if err := s.RegisterKey(ctx, alice.UserID, replacement); err != nil {
		t.Fatal("reset prevented fresh enrollment")
	}
	for _, mutate := range []func(*Key){func(k *Key) { k.KeyID = randomID() }, func(k *Key) { k.UserID = bob.UserID }, func(k *Key) { k.PublicKey = "bad" }, func(k *Key) { k.Vault = nil }, func(k *Key) { k.Vault.Ciphertext = "bad" }, func(k *Key) { k.Vault.Nonce += "=" }} {
		key := testKey(t, uuid.NewString())
		userID := key.UserID
		mutate(&key)
		if err := s.RegisterKey(ctx, userID, key); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted malformed key")
		}
	}
	for _, shape := range []struct {
		size   int64
		chunks int
	}{{0, 1}, {16, 0}, {16, 2}, {ChunkSize + 32, 2}, {32, 4097}} {
		if _, err := s.Allocate(ctx, bob.UserID, shape.size, shape.chunks); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted malformed allocation")
		}
	}
	if _, err := s.GetFile(ctx, alice.UserID, "../"); !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted malformed identifier")
	}
}
func TestConfig(t *testing.T) {
	valid := Config{Database: "/private/documents.db", PublicOrigin: "https://portal.example.test", BasePath: "/auth", Realms: []string{"local"}}
	if err := valid.Validate(); err != nil || valid.MaxUserFiles != 1000 || valid.UploadTTLSeconds != 86400 {
		t.Fatal("configuration defaults")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Database = "relative" }, func(c *Config) { c.PublicOrigin = "http://portal.example.test" }, func(c *Config) { c.PublicOrigin += "/" }, func(c *Config) { c.PublicOrigin = "https://PORTAL.example.test" }, func(c *Config) { c.PublicOrigin = "https://portal.example.test:443" }, func(c *Config) { c.BasePath = "/auth/../api" }, func(c *Config) { c.BasePath = "/auth%2f" }, func(c *Config) { c.Realms = nil }, func(c *Config) { c.Realms = []string{"local", "local"} }, func(c *Config) { c.MaxUserBytes = 1 }, func(c *Config) { c.MaxTotalBytes = -1 }, func(c *Config) { c.UploadTTLSeconds = 1 }, func(c *Config) { c.MaxKeys = -1 }} {
		c := valid
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	var absent *Config
	if absent.Validate() == nil {
		t.Fatal("nil storage configuration accepted")
	}
	empty := Config{}
	if empty.Validate() == nil {
		t.Fatal("empty storage configuration accepted")
	}
}

func TestStoreLocalIdentityBinding(t *testing.T) {
	s, config, alice, _ := testStore(t, func(c *Config) { c.MaxKeys = 2 })
	ctx := t.Context()
	if err := s.BindIdentity(ctx, alice.UserID, "local", "local"); err != nil {
		t.Fatal(err)
	}
	f := testReady(t, s, alice)
	var owner string
	if err := s.db.Read(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT owner FROM files WHERE id=?`, f.ID).Scan(&owner)
	}); err != nil || owner != alice.UserID {
		t.Fatal("file owner is not the local database ID", err)
	}
	other, err := Open(ctx, config, "portal")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, source := range [][2]string{{"other", "local"}, {"local", "other"}} {
		if err := other.BindIdentity(ctx, alice.UserID, source[0], source[1]); !errors.Is(err, ErrIdentityConflict) {
			t.Fatal("colliding ID admitted", err)
		}
	}
	if err := s.ResetKey(ctx, alice.UserID, alice.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := other.BindIdentity(ctx, alice.UserID, "other", "local"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("reset released identity binding", err)
	}
	if err := other.BindIdentity(ctx, alice.UserID, "local", "local"); err != nil {
		t.Fatal("same identity lost binding", err)
	}
	userID := uuid.NewString()
	results := make(chan error, 2)
	for i, store := range []*Store{s, other} {
		go func() { results <- store.BindIdentity(ctx, userID, fmt.Sprintf("store-%d", i), "local") }()
	}
	successes, conflicts := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdentityConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent identity binding was not exclusive")
	}
	if err := s.BindIdentity(ctx, uuid.NewString(), "local", "local"); !errors.Is(err, ErrQuota) {
		t.Fatal("identity reservations exceeded quota", err)
	}
	for _, invalid := range []string{"", randomID(), "00000000-0000-0000-0000-000000000000", "AAAAAAAA-aaaa-4000-8000-aaaaaaaaaaaa", "aaaaaaaa_aaaa-4000-8000-aaaaaaaaaaaa"} {
		if ValidUserID(invalid) || !errors.Is(s.BindIdentity(ctx, invalid, "local", "local"), ErrInvalid) {
			t.Fatal("invalid local ID accepted")
		}
	}
}
