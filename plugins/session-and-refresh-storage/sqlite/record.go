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

package sqlite

import (
	"bytes"
	"encoding/json"
	"io"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

// Private persistence DTOs deliberately retain evidence excluded by the public
// Session's serialization tags. Conversions of Principal/Binding fail to compile
// if the engine's data shape changes, requiring an explicit format review.
type principalRecord struct {
	Backend, Realm, UserID, Subject string
	BackendVersion                  string
	CredentialVersion               uint64
	AuthTime                        int64
	Methods, Challenges             []string
	Audience, Scopes                []string
}

type bindingRecord struct{ Portal, Origin, BasePath, Transport string }

type sessionRecord struct {
	ID                               string
	Principal                        principalRecord
	Binding                          bindingRecord
	Current                          [32]byte
	Revision                         uint64
	IdleExpiresAt, AbsoluteExpiresAt int64
}

func encodeSession(s tokenrefresh.Session) ([]byte, error) {
	if !validSession(s) {
		return nil, tokenrefresh.ErrInvalid
	}
	data, err := json.Marshal(sessionRecord{
		ID: s.ID, Principal: principalRecord(s.Principal), Binding: bindingRecord(s.Binding),
		Current: s.Current, Revision: s.Revision, IdleExpiresAt: s.IdleExpiresAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
	})
	if err != nil || len(data) > 65536 {
		return nil, tokenrefresh.ErrInvalid
	}
	return data, nil
}

func decodeSession(data []byte) (tokenrefresh.Session, error) {
	invalid := tokenrefresh.Session{}
	if len(data) == 0 || len(data) > 65536 {
		return invalid, tokenrefresh.ErrUnavailable
	}
	var record sessionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return invalid, tokenrefresh.ErrUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid, tokenrefresh.ErrUnavailable
	}
	s := tokenrefresh.Session{ID: record.ID, Principal: tokenrefresh.Principal(record.Principal), Binding: tokenrefresh.Binding(record.Binding), Current: record.Current, Revision: record.Revision, IdleExpiresAt: record.IdleExpiresAt, AbsoluteExpiresAt: record.AbsoluteExpiresAt}
	if !validSession(s) {
		return invalid, tokenrefresh.ErrUnavailable
	}
	// Require canonical bytes produced by this version. This also rejects
	// duplicate/unknown/case-variant fields, missing fields and lossy UTF-8.
	encoded, err := encodeSession(s)
	if err != nil || !bytes.Equal(data, encoded) {
		return invalid, tokenrefresh.ErrUnavailable
	}
	return s, nil
}

func validSession(s tokenrefresh.Session) bool {
	if !validText(s.ID, 256) || s.Current == ([32]byte{}) || s.Revision > 100000 || s.Principal.AuthTime <= 0 || s.IdleExpiresAt <= 0 || s.IdleExpiresAt > s.AbsoluteExpiresAt {
		return false
	}
	for _, value := range []string{s.Principal.Backend, s.Principal.Realm, s.Principal.UserID, s.Principal.Subject, s.Binding.Portal, s.Binding.Origin, s.Binding.BasePath} {
		if !validText(value, 4096) {
			return false
		}
	}
	if s.Principal.BackendVersion != "" && !validText(s.Principal.BackendVersion, 4096) {
		return false
	}
	if s.Binding.Transport != tokenrefresh.BodyTransport && s.Binding.Transport != tokenrefresh.CookieTransport {
		return false
	}
	if len(s.Principal.Methods) == 0 {
		return false
	}
	for _, list := range [][]string{s.Principal.Methods, s.Principal.Challenges, s.Principal.Audience, s.Principal.Scopes} {
		if len(list) > 128 {
			return false
		}
		for _, value := range list {
			if !validText(value, 4096) {
				return false
			}
		}
	}
	return true
}
