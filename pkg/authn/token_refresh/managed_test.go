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
	"errors"
	"strings"
	"testing"
)

type managedViewProbe struct {
	*MemoryStore
	generation    Generation
	panicMetadata bool
}

func (v *managedViewProbe) Generation() Generation {
	if v == nil {
		return Generation{}
	}
	if v.panicMetadata {
		panic("private generation canary")
	}
	return v.generation
}

type managedStoreProbe struct {
	config                                             *ExternalStoreConfig
	metadataCalls, readyCalls, activationCalls, closes int
	metadataPanic, readyPanic, activationPanic         bool
	readyError                                         error
	activate                                           func(Generation) (ActiveStore, error)
}

func (s *managedStoreProbe) Metadata() (StoreMetadata, error) {
	if s == nil {
		return StoreMetadata{}, ErrUnavailable
	}
	s.metadataCalls++
	if s.metadataPanic {
		panic("private metadata canary")
	}
	return StoreMetadata{Kind: s.config.Kind, ConfigDigest: s.config.ConfigDigest, MaxSessions: s.config.MaxSessions, MaxRotations: s.config.MaxRotations}, nil
}
func (s *managedStoreProbe) CheckReady(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	s.readyCalls++
	if s.readyPanic {
		panic("private readiness canary")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing readiness bound")
	}
	return s.readyError
}
func (s *managedStoreProbe) ActivateGeneration(_ context.Context, g Generation) (ActiveStore, error) {
	s.activationCalls++
	if s.activationPanic {
		panic("operational activation panic")
	}
	return s.activate(g)
}
func (s *managedStoreProbe) Close() error { s.closes++; return nil }
func managedDescriptor(t *testing.T) *ExternalStoreConfig {
	t.Helper()
	c, err := NewExternalStoreConfig("refresh", "test", 2, 3, struct{ Limit int }{2})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func managedGenerationFixture() Generation {
	return Generation{Namespace: strings.Repeat("a", 64), ID: strings.Repeat("b", 64)}
}

func TestManagedRefreshBindingPreparedOwnership(t *testing.T) {
	descriptor := managedDescriptor(t)
	memory, err := NewMemoryStore(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(memory.Close)
	original := &managedStoreProbe{config: descriptor, activate: func(g Generation) (ActiveStore, error) {
		return &managedViewProbe{MemoryStore: memory, generation: g}, nil
	}}
	input := &ExternalStoreBinding{Config: descriptor, Store: original}
	prepared, err := input.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	replacement := &managedStoreProbe{config: descriptor}
	prepared.Store = replacement
	prepared.Config.Name = "changed"
	input.Config.Kind = "changed"
	next, err := prepared.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if next.Config.Name != "refresh" || next.Config.Kind != "test" {
		t.Fatal("prepared configuration was mutable")
	}
	view, err := next.Activate(t.Context(), managedGenerationFixture())
	if err != nil || view.Generation() != managedGenerationFixture() {
		t.Fatal("prepared activation failed")
	}
	if original.metadataCalls != 1 || original.readyCalls != 1 || original.activationCalls != 1 || original.closes != 0 || replacement.activationCalls != 0 {
		t.Fatal("borrowed preparation changed runtime or ownership")
	}
}

func TestManagedRefreshBindingRejectsInvalidRuntime(t *testing.T) {
	for _, name := range []string{"nil", "typed_nil", "metadata_panic", "readiness_panic", "readiness_error", "mismatch", "canceled"} {
		t.Run(name, func(t *testing.T) {
			c := managedDescriptor(t)
			runtime := &managedStoreProbe{config: c}
			binding := &ExternalStoreBinding{Config: c, Store: runtime}
			ctx := t.Context()
			switch name {
			case "nil":
				binding.Store = nil
			case "typed_nil":
				binding.Store = (*managedStoreProbe)(nil)
			case "metadata_panic":
				runtime.metadataPanic = true
			case "readiness_panic":
				runtime.readyPanic = true
			case "readiness_error":
				runtime.readyError = errors.New("private readiness canary")
			case "mismatch":
				copy := *c
				copy.MaxSessions++
				runtime.config = &copy
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := binding.Prepare(ctx)
			if err == nil || got != nil || strings.Contains(err.Error(), "canary") || runtime.activationCalls != 0 || runtime.closes != 0 {
				t.Fatal("invalid binding escaped preflight or exposed plugin detail")
			}
		})
	}
	for _, name := range []string{"nil_view", "typed_nil_view", "wrong_generation", "generation_panic", "activation_error"} {
		t.Run(name, func(t *testing.T) {
			runtime := &managedStoreProbe{config: managedDescriptor(t), activate: func(g Generation) (ActiveStore, error) {
				switch name {
				case "nil_view":
					return nil, nil
				case "typed_nil_view":
					return (*managedViewProbe)(nil), nil
				case "wrong_generation":
					g.ID = strings.Repeat("c", 64)
				case "generation_panic":
					return &managedViewProbe{generation: g, panicMetadata: true}, nil
				case "activation_error":
					return nil, ErrCommitUncertain
				}
				return &managedViewProbe{generation: g}, nil
			}}
			binding, err := (&ExternalStoreBinding{Config: runtime.config, Store: runtime}).Prepare(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			view, err := binding.Activate(t.Context(), managedGenerationFixture())
			if err == nil || view != nil || strings.Contains(err.Error(), "canary") || runtime.closes != 0 {
				t.Fatal("invalid active view accepted")
			}
			if name == "activation_error" && !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("activation uncertainty classification lost")
			}
		})
	}
}

func TestManagedRefreshDescriptorAndScope(t *testing.T) {
	c := managedDescriptor(t)
	other, err := NewExternalStoreConfig("renamed", "test", 2, 3, struct{ Limit int }{2})
	if err != nil || c.ConfigDigest != other.ConfigDigest {
		t.Fatal("name changed normalized backend digest")
	}
	for _, mutate := range []func(*ExternalStoreConfig){func(c *ExternalStoreConfig) { c.Name = "" }, func(c *ExternalStoreConfig) { c.ConfigDigest = strings.ToUpper(c.ConfigDigest) }, func(c *ExternalStoreConfig) { c.MaxSessions = 0 }, func(c *ExternalStoreConfig) { c.MaxRotations = -1 }} {
		copy := *c
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
	h := newTestManager(t)
	binding := h.manager.binding
	binding.Namespace = managedGenerationFixture().Namespace
	if _, err := NewManager(h.store, h.identity, h.signer, h.manager.policy, binding); err == nil {
		t.Fatal("half-managed scope accepted")
	}
	binding.Generation = managedGenerationFixture().ID
	if _, err := NewManager(h.store, h.identity, h.signer, h.manager.policy, binding); err != nil {
		t.Fatal("complete managed binding rejected")
	}
}

type uncertainAfterIdentity struct{ Identity }

func (i uncertainAfterIdentity) WithIdentity(ctx context.Context, p Principal, apply func(map[string]any) error) error {
	if err := i.Identity.WithIdentity(ctx, p, apply); err != nil {
		return err
	}
	return errors.Join(ErrCommitUncertain, ErrDenied, context.Canceled)
}
func TestRefreshUncertaintyPrecedesDenial(t *testing.T) {
	h := newTestManager(t)
	first := h.issue(t)
	h.manager.identity = uncertainAfterIdentity{h.identity}
	result, err := h.manager.Refresh(t.Context(), first.RefreshToken, CookieTransport)
	if result != nil || !errors.Is(err, ErrCommitUncertain) {
		t.Fatal("uncertain result published or classification lost")
	}
	// This is a core error-ordering test, not a simulated SQLite failure. The
	// successful memory rotation must not trigger an extra denial-based revoke.
	family := h.store.families[first.SessionID]
	if family == nil || family.session.Revision != 1 {
		t.Fatal("joined denial caused a second mutation after uncertainty")
	}
}
