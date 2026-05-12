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
	"net/http"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func (p *Portal) createSandboxUser(ctx context.Context, _ http.ResponseWriter, r *http.Request, rr *requests.Request) (*user.User, error) {
	m := make(map[string]interface{})
	m["sub"] = rr.User.Username
	m["email"] = rr.User.Email
	if rr.User.FullName != "" {
		m["name"] = rr.User.FullName
	}
	if len(rr.User.Roles) > 0 {
		m["roles"] = rr.User.Roles
	}
	m["jti"] = rr.Upstream.SessionID
	m["exp"] = time.Now().Add(time.Duration(5) * time.Second).UTC().Unix()
	m["iat"] = time.Now().UTC().Unix()
	m["nbf"] = time.Now().Add(time.Duration(60) * time.Second * -1).UTC().Unix()
	if _, exists := m["origin"]; !exists {
		m["origin"] = rr.Upstream.Realm
	}
	m["iss"] = util.GetIssuerURL(r)
	m["addr"] = addrutil.GetSourceAddress(r)

	combineGroupRoles(m)

	// Perform user claim transformation if necessary.
	if err := p.transformUser(ctx, rr, m); err != nil {
		return nil, err
	}

	// Inject portal-specific roles.
	injectPortalRoles(m, p.config)
	usr, err := user.NewUser(m)
	if err != nil {
		return nil, err
	}

	// Build a list of additional verification/acceptance challenges.
	if err := p.injectUserChallenges(usr, m, rr.User.Challenges); err != nil {
		p.logger.Warn(
			"user checkpoint injection failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Any("user", m),
			zap.Any("challenges", rr.User.Challenges),
			zap.Error(err),
		)
		rr.Response.Code = http.StatusInternalServerError
		return nil, err
	}

	// Build a list of additional user-specific UI links.
	if v, exists := m["frontend_links"]; exists {
		if err := usr.AddFrontendLinks(v); err != nil {
			p.logger.Warn(
				"frontend link creation failed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Any("user", m),
				zap.Error(err),
			)
			rr.Response.Code = http.StatusInternalServerError
			return nil, err
		}
	}

	usr.Authenticator.Name = rr.Upstream.Name
	usr.Authenticator.Realm = rr.Upstream.Realm
	usr.Authenticator.Method = rr.Upstream.Method
	usr.Authenticator.NextChallenge = usr.Checkpoints[0].Type

	// Grant temporary cookie and redirect to sandbox URL for authentication.
	usr.Authenticator.TempSessionID = util.GetRandomStringFromRange(36, 48)
	usr.Authenticator.TempSecret = util.GetRandomStringFromRange(36, 48)
	return usr, nil
}
