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
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/authchal"
	challengeparser "github.com/greenpau/go-authcrunch/pkg/authchal/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// Empty lists deliberately restore backend defaults; null, missing fields and
// malformed list elements must never become a partial or empty replacement.
func parseProfileAuthChallenges(body map[string]any) ([]string, error) {
	values, ok := body["challenges"].([]any)
	if !ok {
		return nil, fmt.Errorf("challenges must be an array of strings")
	}
	rules := make([]string, 0, len(values))
	for _, value := range values {
		rule, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("challenges must contain only strings")
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return rules, nil
	}
	policy, err := challengeparser.NewAuthenticationChallengeConfigFromDirectives(rules)
	if err != nil {
		return nil, fmt.Errorf("invalid authentication challenge policy")
	}
	for _, rule := range policy.Rules {
		if slices.Contains(rule.Challenges, authchal.EmailKeyword) || slices.Contains(rule.Conditions, authchal.EmailKeyword) {
			return nil, fmt.Errorf("email authentication challenges are unsupported")
		}
	}
	return slices.Clone(policy.Statements), nil
}

func profileAuthChallengeUser(backend ids.IdentityStore, rr *requests.Request) (*identity.User, error) {
	if err := backend.Request(operator.GetUser, rr); err != nil {
		return nil, err
	}
	current, ok := rr.Response.Payload.(*identity.User)
	if !ok || current == nil {
		return nil, fmt.Errorf("invalid identity response")
	}
	return current, nil
}

func profileAuthChallengeBackendError(w http.ResponseWriter, rr *requests.Request, resp map[string]any, err error) error {
	if errors.Is(err, identity.ErrIdentityRequestDenied) || errors.Is(err, errProfileIdentity) {
		resp["message"] = "Profile API requires a current local login"
		return handleAPIProfileResponse(w, rr, http.StatusUnauthorized, resp)
	}
	resp["message"] = "Profile API failed to access authentication challenge rules"
	return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
}

// profileAuthChallengePolicy previews a fresh login from the same request
// context, without signing tokens, caching a sandbox or changing the account.
// The bound backend rechecks this snapshot's credential version on a later write.
func (p *Portal) profileAuthChallengePolicy(ctx context.Context, r *http.Request, rr *requests.Request, usr *user.User, current *identity.User) (map[string]any, error) {
	challenges, err := current.GetChallenges()
	if err != nil {
		return nil, err
	}
	methods := current.GetRegisteredAuthMethods()
	registered := make([]string, 0, len(methods))
	for _, method := range methods {
		if method != authchal.EmailKeyword {
			registered = append(registered, method)
		}
	}
	// Require an actual supported factor for a user-selected generic MFA flow.
	if current.HasAuthChallengeRules() && slices.Contains(challenges, authchal.MfaKeyword) && !slices.Contains(registered, authchal.TotpKeyword) && !slices.Contains(registered, authchal.U2fKeyword) {
		return nil, fmt.Errorf("no supported MFA method is registered")
	}
	preview := requests.NewRequest()
	preview.Upstream = rr.Upstream
	preview.Upstream.Name, preview.Upstream.Realm, preview.Upstream.Method = usr.Authenticator.Name, usr.Authenticator.Realm, usr.Authenticator.Method
	// Start without the backend's explicit-policy marker so the preview can
	// distinguish a portal replacement from the stored preference below.
	preview.User = requests.User{Username: current.Username, Email: current.GetMailClaim(), FullName: current.GetNameClaim(), Roles: current.GetRolesClaim(), Challenges: challenges, AuthMethods: registered}
	loginRequest := r.Clone(ctx)
	loginRequest.Method = http.MethodPost
	loginRequest.URL.Path = path.Join(rr.Upstream.BasePath, "login")
	loginRequest.URL.RawPath, loginRequest.URL.RawQuery = "", ""
	loginRequest.RequestURI = loginRequest.URL.RequestURI()
	claims := sandboxLoginClaims(loginRequest, preview)
	if err := p.transformUser(ctx, preview, claims); err != nil {
		return nil, err
	}
	candidate := &user.User{}
	if err := p.injectUserChallenges(candidate, claims, preview.User.Challenges); err != nil {
		return nil, err
	}
	effective := make([]string, 0, len(candidate.Checkpoints))
	for _, checkpoint := range candidate.Checkpoints {
		effective = append(effective, checkpoint.Type)
	}
	source := "default"
	if current.HasAuthChallengeRules() {
		source = "user"
	}
	if preview.User.AuthChallengePolicy {
		source = "portal"
	}
	additional, _ := claims["challenges"].([]string)
	return map[string]any{
		"entries":               append([]string{}, current.GetAuthChallengeRules()...),
		"registered_methods":    registered,
		"effective_challenges":  effective,
		"additional_challenges": append([]string{}, additional...),
		"policy_source":         source,
	}, nil
}
