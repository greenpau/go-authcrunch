// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package oauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"go.uber.org/zap"
)

type cancelFailureStore struct{ LoginStore }

func (*cancelFailureStore) Cancel(context.Context, string, string, LoginBinding) (bool, error) {
	return true, errors.New("private backend detail")
}

func TestOAuthLoginStoreConstructionAndCancellation(t *testing.T) {
	config := lifecycleOAuthConfig("https://issuer.example")
	config.LoginStore = &LoginStoreConfig{Name: "shared", Namespace: "deployment"}
	if p, err := NewIdentityProvider(config, zap.NewNop()); err == nil {
		p.Close()
		t.Fatal("missing store accepted")
	}
	memory := NewMemoryLoginStore()
	p, err := NewIdentityProviderWithLoginStore(config, zap.NewNop(), memory)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tx := testLoginTransaction("state")
	if err := memory.Create(t.Context(), p.loginNamespace, tx); err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("stranger"))
	if ok, err := p.CancelLoginContext(t.Context(), tx.State, wrong, tx.Binding.Callback); err != nil || ok {
		t.Fatal("wrong browser canceled")
	}
	if ok, err := p.CancelLoginContext(t.Context(), tx.State, tx.Binding.Browser, tx.Binding.Callback); err != nil || !ok {
		t.Fatal("exact cancellation failed")
	}
	broken, err := NewIdentityProviderWithLoginStore(config, zap.NewNop(), &cancelFailureStore{LoginStore: memory})
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	if ok, err := broken.CancelLoginContext(t.Context(), tx.State, tx.Binding.Browser, tx.Binding.Callback); ok || !errors.Is(err, ErrLoginUnavailable) {
		t.Fatal("unconfirmed cancellation reported success")
	}
	if broken.CancelLogin(tx.State, tx.Binding.Browser, tx.Binding.Callback) {
		t.Fatal("legacy cancellation reported success")
	}
	config = lifecycleOAuthConfig("https://issuer.example")
	if p, err := NewIdentityProviderWithLoginStore(config, zap.NewNop(), memory); err == nil {
		p.Close()
		t.Fatal("unexpected runtime binding accepted")
	}
	for _, c := range []*LoginStoreConfig{nil, {}, {Name: "shared"}, {Name: " shared", Namespace: "deployment"}, {Name: "shared", Namespace: "deployment\n"}} {
		if c.Validate() == nil {
			t.Fatal("invalid store configuration accepted")
		}
	}
}
