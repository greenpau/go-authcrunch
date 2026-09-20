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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

type persistentOIDCSession struct {
	Hash                              [32]byte
	Proof                             requests.AuthenticationEvidence
	Realm, Backend, Username, Subject string
	Methods, Challenges               []string
	Consents                          []persistentOIDCConsent
	Expires                           time.Time
}
type persistentOIDCConsent struct {
	ClientID string
	Items    []string
}

type persistentOIDCClaim struct {
	Location, Name string
	Essential      bool
	Values         []byte
}
type persistentOIDCAuthorization struct {
	ClientID, RedirectURI, State, Nonce, Challenge, ResponseMode, HintSubject string
	Scopes, ACRValues                                                         []string
	Claims                                                                    []persistentOIDCClaim
	PromptLogin, PromptConsent, PromptNone                                    bool
	MaxAge                                                                    *int64
	Created, Expires                                                          time.Time
	Session                                                                   [32]byte
	Fresh                                                                     bool
	Consent                                                                   string
}
type persistentOIDCGrant struct {
	Hash, Session, AccessHash, RefreshCurrent [32]byte
	Request                                   persistentOIDCAuthorization
	CodeExpires, Expires, AccessExpires       time.Time
	Redeemed                                  bool
	Revocation                                uint8
	RefreshHashes                             [][32]byte
}
type persistentOIDCState struct {
	Sessions []persistentOIDCSession
	Grants   []persistentOIDCGrant
}

func saveOIDCAuthorization(r oidcAuthorization) (persistentOIDCAuthorization, error) {
	v := persistentOIDCAuthorization{ClientID: r.clientID, RedirectURI: r.redirectURI, State: r.state, Nonce: r.nonce, Challenge: r.challenge, ResponseMode: r.responseMode, HintSubject: r.hintSubject, Scopes: r.scopes, ACRValues: r.acrValues, PromptLogin: r.promptLogin, PromptConsent: r.promptConsent, PromptNone: r.promptNone, MaxAge: r.maxAge, Created: r.created, Expires: r.expires, Session: r.session, Fresh: r.fresh, Consent: r.consent}
	for location, claims := range r.claims {
		for name, c := range claims {
			raw, err := json.Marshal(c.values)
			if err != nil {
				return v, fmt.Errorf("encode OIDC claims state")
			}
			v.Claims = append(v.Claims, persistentOIDCClaim{Location: location, Name: name, Essential: c.essential, Values: raw})
		}
	}
	sort.Slice(v.Claims, func(i, j int) bool {
		if v.Claims[i].Location != v.Claims[j].Location {
			return v.Claims[i].Location < v.Claims[j].Location
		}
		return v.Claims[i].Name < v.Claims[j].Name
	})
	return v, nil
}
func restoreOIDCAuthorization(v persistentOIDCAuthorization) (oidcAuthorization, error) {
	r := oidcAuthorization{clientID: v.ClientID, redirectURI: v.RedirectURI, state: v.State, nonce: v.Nonce, challenge: v.Challenge, responseMode: v.ResponseMode, hintSubject: v.HintSubject, scopes: v.Scopes, acrValues: v.ACRValues, promptLogin: v.PromptLogin, promptConsent: v.PromptConsent, promptNone: v.PromptNone, maxAge: v.MaxAge, created: v.Created, expires: v.Expires, session: v.Session, fresh: v.Fresh, consent: v.Consent, claims: make(oidcClaimsRequest)}
	for _, c := range v.Claims {
		if r.claims[c.Location] == nil {
			r.claims[c.Location] = make(map[string]oidcClaimRequest)
		}
		var values []any
		if json.Unmarshal(c.Values, &values) != nil {
			return r, fmt.Errorf("invalid OIDC claims state")
		}
		r.claims[c.Location][c.Name] = oidcClaimRequest{essential: c.Essential, values: values}
	}

	return r, nil
}

// ConfigurePersistentState restores sessions, consent and grant families before
// publication. The supplied record must bind the issuer, clients, identity and
// signing configuration. All spent code/refresh hashes survive with their family.
// Interactive pending requests are deliberately discarded. The caller owns storage.
func (o *Provider) ConfigurePersistentState(record *state.Record) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if record == nil || o.state != nil || o.closed || len(o.sessions) != 0 || len(o.pending) != 0 || len(o.grants) != 0 {
		return fmt.Errorf("OIDC persistence must be configured before use")
	}
	var snapshot persistentOIDCState
	if _, err := record.Decode(&snapshot); err != nil {
		return err
	}
	if len(snapshot.Sessions) > o.config.MaxSessions || len(snapshot.Grants) > o.config.MaxGrants {
		return fmt.Errorf("persisted OIDC capacity exceeded")
	}
	sessions := make(map[[32]byte]*oidcSession, len(snapshot.Sessions))
	grants := make(map[[32]byte]*oidcGrant, len(snapshot.Grants))
	access := make(map[[32]byte]*oidcGrant)
	refresh := make(map[[32]byte]*oidcGrant)
	for _, s := range snapshot.Sessions {
		if !o.now().Before(s.Expires) {
			continue
		}
		if s.Username == "" || s.Subject == "" || s.Proof.UserID == "" || s.Proof.AuthenticatedAt <= 0 || !o.SupportsRealm(s.Realm) || sessions[s.Hash] != nil {
			return fmt.Errorf("invalid persisted OIDC session")
		}
		consents := make(map[string][]string)
		for _, c := range s.Consents {
			consents[c.ClientID] = c.Items
		}
		sessions[s.Hash] = &oidcSession{proof: s.Proof, realm: s.Realm, backend: s.Backend, username: s.Username, subject: s.Subject, methods: s.Methods, challenges: s.Challenges, consents: consents, expires: s.Expires}
	}
	for _, v := range snapshot.Grants {
		if !o.now().Before(v.Expires) || sessions[v.Session] == nil {
			continue
		}
		request, err := restoreOIDCAuthorization(v.Request)
		if err != nil {
			return err
		}
		client := o.clients[request.clientID]
		if client == nil || !client.isValidRedirectURI(request.redirectURI) || request.session != v.Session || grants[v.Hash] != nil {
			return fmt.Errorf("invalid persisted OIDC grant")
		}
		if v.Revocation != 1 && v.Revocation != 2 {
			return fmt.Errorf("invalid persisted OIDC revocation state")
		}
		g := &oidcGrant{request: request, session: v.Session, codeExpires: v.CodeExpires, expires: v.Expires, redeemed: v.Redeemed, accessHash: v.AccessHash, accessExpires: v.AccessExpires, refreshCurrent: v.RefreshCurrent, refreshHashes: v.RefreshHashes, revoked: v.Revocation == 2}
		grants[v.Hash] = g
		if g.redeemed && !g.revoked && o.now().Before(g.accessExpires) {
			if access[g.accessHash] != nil {
				return fmt.Errorf("duplicate persisted OIDC access hash")
			}
			access[g.accessHash] = g
		}
		for _, hash := range g.refreshHashes {
			if refresh[hash] != nil {
				return fmt.Errorf("duplicate persisted OIDC refresh hash")
			}
			refresh[hash] = g
		}
		if len(g.refreshHashes) > 0 && g.refreshHashes[len(g.refreshHashes)-1] != g.refreshCurrent {
			return fmt.Errorf("invalid persisted OIDC refresh history")
		}
	}
	if len(refresh) > o.config.MaxRefreshTokens {
		return fmt.Errorf("persisted OIDC refresh capacity exceeded")
	}
	o.sessions, o.grants, o.access, o.refresh = sessions, grants, access, refresh
	o.state = record
	return nil
}

// Called with mu held. Issuance invokes this inside the identity transaction.
func (o *Provider) persistState() error {
	if o.state == nil {
		return nil
	}
	var snapshot persistentOIDCState
	for hash, s := range o.sessions {
		if !o.now().Before(s.expires) {
			continue
		}
		var consents []persistentOIDCConsent
		for client, items := range s.consents {
			consents = append(consents, persistentOIDCConsent{ClientID: client, Items: items})
		}
		sort.Slice(consents, func(i, j int) bool { return consents[i].ClientID < consents[j].ClientID })
		snapshot.Sessions = append(snapshot.Sessions, persistentOIDCSession{Hash: hash, Proof: s.proof, Realm: s.realm, Backend: s.backend, Username: s.username, Subject: s.subject, Methods: s.methods, Challenges: s.challenges, Consents: consents, Expires: s.expires})
	}
	for hash, g := range o.grants {
		if !o.now().Before(g.expires) || o.sessions[g.session] == nil {
			continue
		}
		request, err := saveOIDCAuthorization(g.request)
		if err != nil {
			o.closed = true
			return err
		}
		revocation := uint8(1)
		if g.revoked {
			revocation = 2
		}
		snapshot.Grants = append(snapshot.Grants, persistentOIDCGrant{Hash: hash, Session: g.session, Request: request, CodeExpires: g.codeExpires, Expires: g.expires, Redeemed: g.redeemed, AccessHash: g.accessHash, AccessExpires: g.accessExpires, RefreshCurrent: g.refreshCurrent, RefreshHashes: g.refreshHashes, Revocation: revocation})
	}
	sort.Slice(snapshot.Sessions, func(i, j int) bool {
		return bytes.Compare(snapshot.Sessions[i].Hash[:], snapshot.Sessions[j].Hash[:]) < 0
	})
	sort.Slice(snapshot.Grants, func(i, j int) bool { return bytes.Compare(snapshot.Grants[i].Hash[:], snapshot.Grants[j].Hash[:]) < 0 })
	prepared, err := o.state.PrepareEncode(snapshot)
	if err != nil {
		if !errors.Is(err, state.ErrCapacity) {
			o.closed = true
		}
		return err
	}
	if err := o.state.Save(prepared); err != nil {
		o.closed = true
		return err
	}
	return nil
}

func (o *Provider) persistResponse(w http.ResponseWriter) {
	if o.persistState() == nil {
		return
	}
	// HandleHTTP buffers protocol responses. Discard credentials/redirects before
	// sending an unavailable error when a durable commit fails.
	if response, ok := w.(*oidcHTTPResponse); ok {
		*response = oidcHTTPResponse{header: make(http.Header)}
	}
	oidcHeaders(w)
	oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
}
