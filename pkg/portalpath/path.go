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

// Package portalpath validates declared authentication portal mounts.
package portalpath

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

// ErrShape identifies a noncanonical absolute mount declaration.
var ErrShape = errors.New("portal mount requires a canonical absolute path")

// ErrReservedPrefix identifies a segment starting with a legacy endpoint word.
var ErrReservedPrefix = errors.New("portal mount uses a reserved endpoint prefix")

// ErrReservedSegment identifies a complete segment owned by a portal namespace.
var ErrReservedSegment = errors.New("portal mount uses a reserved endpoint segment")

// Validate checks a literal mount without normalization or I/O. Root is `/`;
// other paths have no trailing slash. Mounts use visible ASCII without semicolons
// and require no URL escaping, so browser proof cookie Path attributes preserve
// their exact scope on the wire.
// Reservations apply case-sensitively to every segment of the declaration,
// never to realms or data inside a route.
// The independent authored route catalogue qualifies these production rules.
func Validate(basePath string) error {
	if basePath == "" || !strings.HasPrefix(basePath, "/") || path.Clean(basePath) != basePath || (&url.URL{Path: basePath}).EscapedPath() != basePath || strings.ContainsAny(basePath, "%?#\\{}*[];") || strings.IndexFunc(basePath, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		return ErrShape
	}
	for segment := range strings.SplitSeq(strings.Trim(basePath, "/"), "/") {
		for _, prefix := range []string{"profile", "portal", "recover", "forgot", "register", "whoami", "logout", "favicon", "beacon", "login"} {
			if strings.HasPrefix(segment, prefix) {
				return ErrReservedPrefix
			}
		}
		switch segment {
		case "operator", "documents", "connected-accounts", ".well-known", "api", "apps", "assets", "barcode", "basic", "cross-device", "oauth2", "oidc", "provider", "qrcode", "saml", "sandbox":
			return ErrReservedSegment
		}
	}
	return nil
}
