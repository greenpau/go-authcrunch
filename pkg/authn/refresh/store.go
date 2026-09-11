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
// Spent digests must survive until the family's absolute deadline. Unknown
// credentials and wrong bindings must never revoke other sessions.
type Store interface {
	Create(context.Context, Session, int64) error
	Lookup(context.Context, [32]byte, Binding) (Session, error)
	Rotate(context.Context, Session, [32]byte, int64, int64) error
	Revoke(context.Context, [32]byte, Binding) error
}

func cloneSession(s Session) Session {
	s.Principal.Methods = append([]string(nil), s.Principal.Methods...)
	s.Principal.Challenges = append([]string(nil), s.Principal.Challenges...)
	s.Principal.Audience = append([]string(nil), s.Principal.Audience...)
	s.Principal.Scopes = append([]string(nil), s.Principal.Scopes...)
	return s
}
