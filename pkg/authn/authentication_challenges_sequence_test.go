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

package authn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type challengeSequenceStore struct {
	ids.IdentityStore
	lookups int
}

func (*challengeSequenceStore) GetRealm() string { return "local" }

func (s *challengeSequenceStore) Request(op operator.Type, rr *requests.Request) error {
	if op != operator.GetMfaTokens {
		return fmt.Errorf("unexpected backend operation")
	}
	s.lookups++
	bundle := identity.NewMfaTokenBundle()
	bundle.Add(&identity.MfaToken{Type: "u2f", Parameters: map[string]string{"u2f_id": "credential", "u2f_type": "public-key"}})
	rr.Response.Payload = bundle
	return nil
}

func TestAuthenticationChallengeWebAuthnWaitsForAssertion(t *testing.T) {
	for _, sequence := range [][]string{{"u2f"}, {"u2f", "password"}, {"u2f", "totp"}, {"mfa", "password"}} {
		t.Run(strings.Join(sequence, "_"), func(t *testing.T) {
			store := &challengeSequenceStore{}
			p := &Portal{identityStores: []ids.IdentityStore{store}}
			checkpoints, err := user.NewCheckpoints(sequence)
			if err != nil {
				t.Fatal(err)
			}
			usr := &user.User{LoginUsername: "alice", Checkpoints: checkpoints, Authenticator: user.Authenticator{Realm: "local"}}
			rr := requests.NewRequest()
			r := httptest.NewRequest(http.MethodPost, "https://portal.example.test/auth/login", nil)
			auth := &apiauth.AuthRequest{ChallengeKind: sequence[0], ChallengeResponse: "webauthn"}
			if err := p.handleSandboxCheckpointVerification(t.Context(), r, rr, usr, auth); err != nil {
				t.Fatal(err)
			}
			if rr.Response.Authenticated || usr.Authorized || store.lookups != 1 {
				t.Fatal("challenge issuance advanced authentication")
			}
			for _, checkpoint := range usr.Checkpoints {
				if checkpoint.Passed || checkpoint.Method != "" || checkpoint.FailedAttempts != 0 {
					t.Fatal("challenge issuance modified checkpoint evidence")
				}
			}
			encoded := strings.TrimPrefix(usr.Authenticator.NextChallenge, "mfa:u2f:")
			data, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var challenge struct{ Challenge string }
			if err := json.Unmarshal(data, &challenge); err != nil || challenge.Challenge == "" || challenge.Challenge != usr.Authenticator.TempChallenge || usr.Checkpoints[0].Type != "u2f" {
				t.Fatal("missing server-bound assertion challenge", err)
			}
		})
	}
}
