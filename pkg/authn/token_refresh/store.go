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

import "context"

const (
	// CookieTransport keeps both credentials out of browser JavaScript.
	CookieTransport = "cookie"
	// BodyTransport is an explicitly enabled native-client grant.
	BodyTransport = "body"
)

// Principal is server-only evidence of a completed authentication. Issue callers
// must redeem that evidence once; possession of an access JWT is insufficient.
type Principal struct {
	Backend, Realm, UserID, Subject string   `json:"-" xml:"-" yaml:"-"`
	BackendVersion                  string   `json:"-" xml:"-" yaml:"-"`
	CredentialVersion               uint64   `json:"-" xml:"-" yaml:"-"`
	AuthTime                        int64    `json:"-" xml:"-" yaml:"-"`
	Methods, Challenges             []string `json:"-" xml:"-" yaml:"-"`
	Audience, Scopes                []string `json:"-" xml:"-" yaml:"-"`
}

// Binding is stable across compatible portal instances and fixes transport.
type Binding struct {
	Portal, Origin, BasePath, Transport string `json:"-" xml:"-" yaml:"-"`
}

// Session is a value snapshot. Stores must not retain caller-owned slices.
type Session struct {
	ID                               string    `json:"-" xml:"-" yaml:"-"`
	Principal                        Principal `json:"-" xml:"-" yaml:"-"`
	Binding                          Binding   `json:"-" xml:"-" yaml:"-"`
	Current                          [32]byte  `json:"-" xml:"-" yaml:"-"`
	Revision                         uint64    `json:"-" xml:"-" yaml:"-"`
	IdleExpiresAt, AbsoluteExpiresAt int64     `json:"-" xml:"-" yaml:"-"`
}

// Store operations are atomic across all users of an adapter. Lookup and Rotate
// must revoke the family on a known spent credential with the matching binding.
// Rotate must recheck digest, revision, revocation and deadlines at commit time.
// Spent digests must survive while any descendant remains usable. An adapter
// may discard a whole family after revocation, idle/absolute expiry, or rotation
// exhaustion; it must never discard only the spent history of a live family.
// Unknown credentials and wrong bindings must never revoke other sessions.
// Create callers must generate fresh unpredictable IDs and credentials, never
// resurrect old Session snapshots. Stores need not retain terminal tombstones.
type Store interface {
	Create(context.Context, Session, int64) error
	Lookup(context.Context, [32]byte, Binding) (Session, error)
	Rotate(context.Context, Session, [32]byte, int64, int64) error
	Revoke(context.Context, [32]byte, Binding) error
}

// ReplacementStore is an optional extension for fresh-login replacement at full
// capacity. CreateReplacing must validate the new session and staged access
// deadline, identify previous current or spent credentials with the new binding,
// and atomically retire those families and create the new one. Every live family
// must survive a failed commit. Unknown credentials and other bindings are
// ignored. Duplicate credentials count only once. New IDs/digests must not
// collide with retained families, including the families being replaced.
// This is fresh issuance after independently completed authentication, not a
// refresh exchange or a grace window for spent credentials.
type ReplacementStore interface {
	Store
	CreateReplacing(context.Context, Session, int64, [][32]byte) error
}

func cloneSession(s Session) Session {
	s.Principal.Methods = append([]string(nil), s.Principal.Methods...)
	s.Principal.Challenges = append([]string(nil), s.Principal.Challenges...)
	s.Principal.Audience = append([]string(nil), s.Principal.Audience...)
	s.Principal.Scopes = append([]string(nil), s.Principal.Scopes...)
	return s
}
