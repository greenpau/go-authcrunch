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

package tokenrefresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// StoreMetadata attests an initialized immutable managed store configuration.
// Limits apply to the entire underlying store, including all namespaces.
type StoreMetadata struct {
	Kind         string `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty" xml:"config_digest,omitempty" yaml:"config_digest,omitempty"`
	MaxSessions  int    `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxRotations int    `json:"max_rotations,omitempty" xml:"max_rotations,omitempty" yaml:"max_rotations,omitempty"`
}

// ExternalStoreConfig declares a borrowed managed store without a runtime handle.
// Construct it from the backend's validated, normalized configuration.
type ExternalStoreConfig struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Kind         string `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty" xml:"config_digest,omitempty" yaml:"config_digest,omitempty"`
	MaxSessions  int    `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxRotations int    `json:"max_rotations,omitempty" xml:"max_rotations,omitempty" yaml:"max_rotations,omitempty"`
}

// Generation is one immutable namespace and configuration generation. Both are
// independently generated 32-byte identities encoded as lowercase hexadecimal.
type Generation struct {
	Namespace string `json:"-" xml:"-" yaml:"-"`
	ID        string `json:"-" xml:"-" yaml:"-"`
}

// ActiveStore is a borrowed view bound to one immutable generation. Every
// operation must check the current marker in its own transaction before acting.
type ActiveStore interface {
	ReplacementStore
	SessionValidator
	Generation() Generation
}

// ManagedStore supplies metadata and readiness before generation activation.
// The host owns its lifetime; activation never transfers ownership of the view.
type ManagedStore interface {
	Metadata() (StoreMetadata, error)
	CheckReady(context.Context) error
	ActivateGeneration(context.Context, Generation) (ActiveStore, error)
}

// ExternalStoreBinding contains runtime-only inputs. Prepare captures an
// immutable private snapshot; replacing exported inputs after Prepare has no
// effect on subsequent preparation or activation. The store remains borrowed.
type ExternalStoreBinding struct {
	Config   *ExternalStoreConfig `json:"-" xml:"-" yaml:"-"`
	Store    ManagedStore         `json:"-" xml:"-" yaml:"-"`
	prepared *preparedExternalStore
}

type preparedExternalStore struct {
	config ExternalStoreConfig
	store  ManagedStore
}

// NewExternalStoreConfig hashes a validated normalized backend configuration.
// The declaration name is excluded from the digest and all runtime handles.
func NewExternalStoreConfig(name, kind string, maxSessions, maxRotations int, normalizedConfig any) (*ExternalStoreConfig, error) {
	data, err := json.Marshal(normalizedConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid managed refresh store configuration")
	}
	hash := sha256.Sum256(data)
	cfg := &ExternalStoreConfig{Name: name, Kind: kind, ConfigDigest: hex.EncodeToString(hash[:]), MaxSessions: maxSessions, MaxRotations: maxRotations}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks declarative metadata without accessing a backend or files.
func (c *ExternalStoreConfig) Validate() error {
	if c == nil || !managedStoreText(c.Name) || !managedStoreText(c.Kind) || !managedIdentity(c.ConfigDigest) || c.MaxSessions < 1 || c.MaxRotations < 1 {
		return fmt.Errorf("invalid managed refresh store declaration")
	}
	return nil
}

func managedStoreText(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}
func managedIdentity(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validGeneration(g Generation) bool { return managedIdentity(g.Namespace) && managedIdentity(g.ID) }

func managedMetadata(store ManagedStore) (_ StoreMetadata, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid managed refresh store metadata")
		}
	}()
	metadata, err := store.Metadata()
	if err != nil {
		return StoreMetadata{}, fmt.Errorf("invalid managed refresh store metadata")
	}
	return metadata, nil
}
func managedReady(ctx context.Context, store ManagedStore) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("managed refresh store is unavailable")
		}
	}()
	if err := store.CheckReady(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("managed refresh store is unavailable")
	}
	return ctx.Err()
}

// Prepare validates metadata and bounded read-only readiness once. It never
// activates a generation, writes a probe family, or closes a borrowed handle.
func (b *ExternalStoreBinding) Prepare(ctx context.Context) (*ExternalStoreBinding, error) {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	prepared := b.prepared
	if prepared == nil {
		if b.Config.Validate() != nil || b.Store == nil {
			return nil, fmt.Errorf("invalid managed refresh store binding")
		}
		config := *b.Config
		metadata, err := managedMetadata(b.Store)
		if err != nil || metadata.Kind != config.Kind || metadata.ConfigDigest != config.ConfigDigest || metadata.MaxSessions != config.MaxSessions || metadata.MaxRotations != config.MaxRotations {
			return nil, fmt.Errorf("managed refresh store metadata does not match declaration")
		}
		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := managedReady(readyCtx, b.Store); err != nil {
			return nil, err
		}
		prepared = &preparedExternalStore{config: config, store: b.Store}
	}
	config := prepared.config
	return &ExternalStoreBinding{Config: &config, Store: prepared.store, prepared: prepared}, nil
}

func activeGeneration(store ActiveStore) (_ Generation, err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return store.Generation(), nil
}

// Activate returns the backend's exact borrowed immutable view after validating
// its generation. Backend activation is operational work, outside panic recovery.
func (b *ExternalStoreBinding) Activate(ctx context.Context, generation Generation) (ActiveStore, error) {
	if b == nil || b.prepared == nil || ctx == nil || ctx.Err() != nil || !validGeneration(generation) {
		return nil, ErrUnavailable
	}
	view, err := b.prepared.store.ActivateGeneration(ctx, generation)
	if err != nil {
		return nil, err
	}
	if view == nil {
		return nil, ErrUnavailable
	}
	actual, err := activeGeneration(view)
	if err != nil || actual != generation || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return view, nil
}
