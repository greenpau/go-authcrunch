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
	"fmt"
	"net/http"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// checkDirectAuthenticationPolicy prevents a non-sandbox login from treating
// selected challenges as completed. Basic authentication must satisfy every
// effective checkpoint. API keys retain their independent default behavior only
// when neither an explicit policy nor an additive requirement applies.
func (p *Portal) checkDirectAuthenticationPolicy(rr *requests.Request, claims map[string]any, completed []string) error {
	_, additional := claims["challenges"]
	if len(completed) == 0 && !rr.User.AuthChallengePolicy && !additional {
		return nil
	}
	candidate := &user.User{}
	if err := p.injectUserChallenges(candidate, claims, rr.User.Challenges); err != nil {
		rr.Response.Code = http.StatusForbidden
		return err
	}
	for _, c := range candidate.Checkpoints {
		if !slices.Contains(completed, c.Type) {
			rr.Response.Code = http.StatusForbidden
			return fmt.Errorf("authentication method does not satisfy selected policy")
		}
	}
	return nil
}
