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

package refresh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Policy bounds renewal relative to the original authentication event.
type Policy struct {
	AccessLifetime, IdleTimeout, AbsoluteTimeout time.Duration `json:"-" xml:"-" yaml:"-"`
}

// Identity resolves fresh attributes and checks security versions and required
// challenges. It must serialize security mutations with the supplied callback,
// which signs and atomically commits credentials. It must not call back on denial
// or outage. ErrDenied is definitive; other errors leave the credential usable.
type Identity interface {
	WithIdentity(context.Context, Principal, func(map[string]any) error) error
}

// Signer signs canonical claims without changing their grant or deadlines.
type Signer interface {
	Sign(context.Context, map[string]any) (string, error)
}

// Result is issued only after commit. RefreshToken must never be logged.
type Result struct {
	AccessToken, RefreshToken                            string         `json:"-" xml:"-" yaml:"-"`
	SessionID                                            string         `json:"-" xml:"-" yaml:"-"`
	AccessExpiresAt, RefreshExpiresAt, AbsoluteExpiresAt int64          `json:"-" xml:"-" yaml:"-"`
	Claims                                               map[string]any `json:"-" xml:"-" yaml:"-"`
}

// Manager separates authentication, issuance, rotation, and delivery.
type Manager struct {
	store    Store
	identity Identity
	signer   Signer
	policy   Policy
	binding  Binding
	now      func() time.Time
}

// NewManager constructs a portal-bound issuer. Body transport is selected by
// trusted login code, after checking that native transport is enabled.
func NewManager(store Store, identity Identity, signer Signer, policy Policy, binding Binding) (*Manager, error) {
	if store == nil || identity == nil || signer == nil {
		return nil, fmt.Errorf("refresh dependencies are required")
	}
	if policy.AccessLifetime < time.Second || policy.IdleTimeout < time.Second || policy.AbsoluteTimeout < time.Second || policy.AccessLifetime > policy.AbsoluteTimeout || policy.IdleTimeout > policy.AbsoluteTimeout {
		return nil, fmt.Errorf("invalid refresh lifetimes")
	}
	if binding.Portal == "" || binding.Origin == "" || binding.BasePath == "" {
		return nil, fmt.Errorf("refresh binding is required")
	}
	return &Manager{store: store, identity: identity, signer: signer, policy: policy, binding: binding, now: time.Now}, nil
}

func (m *Manager) transportBinding(transport string) (Binding, error) {
	if transport != CookieTransport && transport != BodyTransport {
		return Binding{}, ErrInvalid
	}
	b := m.binding
	b.Transport = transport
	return b, nil
}

// Issue consumes trusted, already redeemed login evidence. It does not accept
// access tokens or request-supplied claims as proof of authentication.
func (m *Manager) Issue(ctx context.Context, p Principal, transport string) (*Result, error) {
	b, err := m.transportBinding(transport)
	if err != nil {
		return nil, err
	}
	now := m.now().Unix()
	if p.UserID == "" || p.Backend == "" || p.Realm == "" || p.Subject == "" || p.AuthTime <= 0 || p.AuthTime > now || len(p.Methods) == 0 {
		return nil, ErrDenied
	}
	id, err := randomID()
	if err != nil {
		return nil, ErrUnavailable
	}
	s := Session{ID: id, Principal: p, Binding: b, AbsoluteExpiresAt: p.AuthTime + int64(m.policy.AbsoluteTimeout/time.Second)}
	var result *Result
	err = m.identity.WithIdentity(ctx, p, func(claims map[string]any) error {
		var err error
		s.Principal.Audience, err = audienceList(claims["aud"])
		if err != nil {
			return err
		}
		s.Principal.Scopes, err = scopes(claims)
		if err != nil {
			return err
		}
		result, err = m.prepare(ctx, s, claims)
		if err != nil {
			return err
		}
		s.Current, err = digest(result.RefreshToken)
		if err != nil {
			return err
		}
		s.IdleExpiresAt = result.RefreshExpiresAt
		return m.store.Create(ctx, s, result.AccessExpiresAt)
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// Refresh stages signing before an atomic credential replacement. Signing or
// directory failures do not consume the credential. A lost response after commit
// cannot safely be retried: strict replay detection revokes the family.
func (m *Manager) Refresh(ctx context.Context, token, transport string) (*Result, error) {
	d, err := digest(token)
	if err != nil {
		return nil, err
	}
	b, err := m.transportBinding(transport)
	if err != nil {
		return nil, err
	}
	s, err := m.store.Lookup(ctx, d, b)
	if err != nil {
		return nil, err
	}
	var result *Result
	err = m.identity.WithIdentity(ctx, s.Principal, func(claims map[string]any) error {
		var err error
		result, err = m.prepare(ctx, s, claims)
		if err != nil {
			return err
		}
		next, err := digest(result.RefreshToken)
		if err != nil {
			return err
		}
		return m.store.Rotate(ctx, s, next, result.RefreshExpiresAt, result.AccessExpiresAt)
	})
	if errors.Is(err, ErrDenied) {
		if revokeErr := m.store.Revoke(ctx, d, b); revokeErr != nil {
			return nil, revokeErr
		}
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// Logout revokes the family without validating an access JWT.
func (m *Manager) Logout(ctx context.Context, token, transport string) error {
	d, err := digest(token)
	if err != nil {
		return err
	}
	b, err := m.transportBinding(transport)
	if err != nil {
		return err
	}
	return m.store.Revoke(ctx, d, b)
}

func (m *Manager) prepare(ctx context.Context, s Session, source map[string]any) (*Result, error) {
	now := m.now().Unix()
	if now >= s.AbsoluteExpiresAt {
		return nil, ErrDenied
	}
	accessExpiry := min(now+int64(m.policy.AccessLifetime/time.Second), s.AbsoluteExpiresAt)
	idleExpiry := min(now+int64(m.policy.IdleTimeout/time.Second), s.AbsoluteExpiresAt)
	jti, err := randomID()
	if err != nil {
		return nil, ErrUnavailable
	}
	token, _, err := newToken()
	if err != nil {
		return nil, ErrUnavailable
	}
	claims := make(map[string]any, len(source)+10)
	for k, v := range source {
		claims[k] = v
	}
	// Transformations may supply application claims, but cannot rewrite proof.
	for _, k := range []string{"acr", "scope", "scopes", "challenges"} {
		delete(claims, k)
	}
	aud, err := audienceList(source["aud"])
	if err != nil {
		return nil, err
	}
	scope, err := scopes(source)
	if err != nil {
		return nil, err
	}
	aud = intersect(aud, s.Principal.Audience)
	// Removing all authorized audiences must not become an unrestricted JWT
	// through omission of the aud claim during serialization.
	if len(s.Principal.Audience) > 0 && len(aud) == 0 {
		return nil, ErrDenied
	}
	claims["aud"] = aud
	claims["scopes"] = intersect(scope, s.Principal.Scopes)
	claims["sub"], claims["iss"] = s.Principal.Subject, s.Binding.Origin+strings.TrimSuffix(s.Binding.BasePath, "/")
	claims["origin"], claims["realm"] = s.Principal.Realm, s.Principal.Realm
	claims["sid"], claims["jti"] = s.ID, jti
	claims["iat"], claims["nbf"], claims["exp"] = now, now, accessExpiry
	claims["auth_time"] = s.Principal.AuthTime
	claims["amr"] = append([]string(nil), s.Principal.Methods...)
	accessToken, err := m.signer.Sign(ctx, claims)
	if err != nil || accessToken == "" {
		return nil, ErrUnavailable
	}
	return &Result{AccessToken: accessToken, RefreshToken: token, SessionID: s.ID, AccessExpiresAt: accessExpiry, RefreshExpiresAt: idleExpiry, AbsoluteExpiresAt: s.AbsoluteExpiresAt, Claims: claims}, nil
}

func stringList(v any) ([]string, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		return strings.Fields(v), nil
	case []string:
		return append([]string(nil), v...), nil
	case []any:
		values := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, ErrDenied
			}
			values = append(values, s)
		}
		return values, nil
	default:
		return nil, ErrDenied
	}
}

func audienceList(v any) ([]string, error) {
	if s, ok := v.(string); ok {
		return []string{s}, nil
	}
	return stringList(v)
}

func scopes(m map[string]any) ([]string, error) {
	a, err := stringList(m["scopes"])
	if err != nil {
		return nil, err
	}
	b, err := stringList(m["scope"])
	return append(a, b...), err
}

func intersect(current, original []string) []string {
	allowed := make(map[string]bool, len(original))
	for _, s := range original {
		allowed[s] = true
	}
	result := []string{}
	for _, s := range current {
		if allowed[s] {
			result = append(result, s)
			delete(allowed, s)
		}
	}
	return result
}
