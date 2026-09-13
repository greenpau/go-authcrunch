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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// ErrIdentityDenied reports stale, revoked, or otherwise ineligible login evidence.
var ErrIdentityDenied = errors.New("oidc identity denied")

// Provider implements an OpenID Provider backed by an IdentityVerifier.
// Construct it with NewProvider; a Provider must not be copied after use.
type Provider struct {
	verifier                                    IdentityVerifier
	loginURL                                    string
	config                                      Config
	origin, mount, sessionCookie, requestCookie string
	keys                                        []oidcSigningKey
	clients                                     map[string]*ClientConfig
	mu                                          sync.Mutex
	sessions                                    map[[32]byte]*oidcSession
	pending                                     map[[32]byte]*oidcAuthorization
	grants                                      map[[32]byte]*oidcGrant
	access                                      map[[32]byte]*oidcGrant
	nextSweep                                   time.Time
	closed                                      bool
	now                                         func() time.Time
	consentTemplate, formPostTemplate           *template.Template
}

type oidcSession struct {
	proof                             requests.AuthenticationEvidence
	realm, backend, username, subject string
	methods, challenges               []string
	consents                          map[string][]string
	expires                           time.Time
}

func (o *Provider) hasConsent(s *oidcSession, request *oidcAuthorization) bool {
	if s == nil {
		return false
	}
	if o.clients[request.clientID].SkipConsent {
		return true
	}
	for _, scope := range request.scopes {
		if !slices.Contains(s.consents[request.clientID], scope) {
			return false
		}
	}
	return true
}

type oidcAuthorization struct {
	clientID, redirectURI, state, nonce, challenge, responseMode, hintSubject string
	scopes                                                                    []string
	promptLogin, promptConsent, promptNone                                    bool
	maxAge                                                                    *int64
	created, expires                                                          time.Time
	session                                                                   [32]byte
	// A continuation requires a newly completed login when fresh is true.
	fresh   bool
	consent string
}

type oidcGrant struct {
	request              oidcAuthorization
	session              [32]byte
	codeExpires, expires time.Time
	redeemed             bool
	accessHash           [32]byte
}

// Close invalidates all browser sessions and grants. It is safe to call repeatedly.
func (o *Provider) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	clear(o.sessions)
	clear(o.pending)
	clear(o.grants)
	clear(o.access)
}

// All state access uses mu. Identity callbacks execute while holding mu, then
// acquire the local store/database lock. Database callbacks never reenter OIDC.
func (o *Provider) sweep() {
	now := o.now()
	if now.Before(o.nextSweep) {
		return
	}
	o.nextSweep = now.Add(time.Second)
	for hash, session := range o.sessions {
		if !now.Before(session.expires) {
			delete(o.sessions, hash)
		}
	}
	for hash, request := range o.pending {
		if !now.Before(request.expires) {
			delete(o.pending, hash)
		}
	}
	for hash, grant := range o.grants {
		if !now.Before(grant.expires) {
			delete(o.grants, hash)
			delete(o.access, grant.accessHash)
		}
	}
}

func oidcRandom() string {
	// crypto/rand.Read either fills the entire buffer or terminates the process
	// on an unrecoverable entropy failure (Go 1.26).
	var value [32]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func oidcCookieHash(r *http.Request, name string) [32]byte {
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		return [32]byte{}
	}
	return sha256.Sum256([]byte(cookies[0].Value))
}

func (o *Provider) cookie(w http.ResponseWriter, name, value string, lifetime int) {
	expires := o.now().Add(time.Duration(lifetime) * time.Second)
	if lifetime < 0 {
		expires = time.Unix(1, 0)
	}
	path := o.mount
	if path == "" {
		path = "/"
	}
	// Names follow the portal cookie factory. Provider credentials stay
	// host-only and scoped to the issuer mount, with their own bounded lifetime.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: lifetime, Expires: expires})
}

func (o *Provider) originOK(r *http.Request) bool {
	secure := r.TLS != nil || r.URL.Scheme == "https"
	if value := r.Header.Get("X-Forwarded-Proto"); value != "" {
		secure = value == "https"
	}
	return secure && "https://"+addrutil.GetSourceHost(r) == o.origin && r.URL.RawPath == ""
}

func (o *Provider) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != o.origin) {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return o.originOK(r) && (site == "" || site == "same-origin" || site == "none")
}

func (o *Provider) withIdentity(ctx context.Context, s *oidcSession, apply func(map[string]any) error) error {
	if s == nil || !o.now().Before(s.expires) {
		return ErrIdentityDenied
	}
	proof := Authentication{Realm: s.realm, Backend: s.backend, Username: s.username, Evidence: s.proof, Methods: slices.Clone(s.methods), Challenges: slices.Clone(s.challenges)}
	return o.verifier.WithIdentity(ctx, proof, func(current Identity) error {
		if current.Username != s.username {
			return ErrIdentityDenied
		}
		return apply(map[string]any{"sub": s.subject, "name": current.Name, "preferred_username": current.Username, "email": current.Email, "email_verified": current.EmailVerified})
	})
}

// CompleteLogin replaces the browser session using trusted, completed login evidence.
// Call it only after authentication and all required challenges succeed. It verifies
// current identity atomically before publishing a cookie. Native clients should not
// call this browser API. A Location header resumes pending authorization, if any.
// Unsupported realms clear the old session without creating an OIDC session.
func (o *Provider) CompleteLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, proof Authentication) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sweep()
	previous := oidcCookieHash(r, o.sessionCookie)
	delete(o.sessions, previous)
	o.cookie(w, o.sessionCookie, "", -1)
	if !o.SupportsRealm(proof.Realm) {
		return nil
	}
	if !o.sameOrigin(r) || o.closed || proof.Backend == "" || proof.Username == "" || proof.Evidence.UserID == "" || proof.Evidence.AuthenticatedAt <= 0 || len(proof.Methods) == 0 {
		return ErrIdentityDenied
	}
	s := &oidcSession{proof: proof.Evidence, realm: proof.Realm, backend: proof.Backend, username: proof.Username, methods: slices.Clone(proof.Methods), expires: o.now().Add(time.Duration(o.config.SessionLifetimeSeconds) * time.Second)}
	s.challenges = slices.Clone(proof.Challenges)
	// Length-delimited input prevents ambiguity between backend/realm/user ID.
	subject, _ := json.Marshal([]string{s.backend, s.realm, s.proof.UserID})
	digest := sha256.Sum256(subject)
	s.subject = base64.RawURLEncoding.EncodeToString(digest[:])
	if len(o.sessions) >= o.config.MaxSessions {
		return fmt.Errorf("oidc session capacity reached")
	}
	return o.withIdentity(ctx, s, func(map[string]any) error {
		credential := oidcRandom()
		hash := sha256.Sum256([]byte(credential))
		o.sessions[hash] = s
		o.cookie(w, o.sessionCookie, credential, o.config.SessionLifetimeSeconds)
		if pending := o.pending[oidcCookieHash(r, o.requestCookie)]; pending != nil && o.now().Before(pending.expires) {
			pending.session, pending.fresh = hash, false
			w.Header().Set("Location", o.config.Issuer+"/oidc/continue")
		}
		return nil
	})
}

// Logout revokes the browser session and pending authorization, then clears both cookies.
// The embedding application must authorize the logout request before calling it.
func (o *Provider) Logout(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.sessions, oidcCookieHash(r, o.sessionCookie))
	delete(o.pending, oidcCookieHash(r, o.requestCookie))
	o.cookie(w, o.sessionCookie, "", -1)
	o.cookie(w, o.requestCookie, "", -1)
}

// ClearSession revokes a browser session while retaining its pending authorization.
// Use it when beginning a fresh interactive login.
func (o *Provider) ClearSession(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.sessions, oidcCookieHash(r, o.sessionCookie))
	o.cookie(w, o.sessionCookie, "", -1)
}
