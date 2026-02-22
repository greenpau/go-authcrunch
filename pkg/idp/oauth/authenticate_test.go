// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package oauth

import (
	"fmt"
	"math/rand"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func TestAuthenticate(t *testing.T) {
	// For "state"
	uuid.SetRand(rand.New(rand.NewSource(1)))
	defer uuid.SetRand(nil)

	testcases := []struct {
		name      string
		config    *Config
		logger    *zap.Logger
		shouldErr bool
		errPhase  string
		err       error
		request   requests.Request
		want      requests.Response
	}{
		{
			name: "discord provider with overridden urls",
			config: &Config{
				Name:             "discord",
				Realm:            "discord",
				Driver:           "discord",
				ClientID:         "foo",
				ClientSecret:     "bar",
				AuthorizationURL: "https://discordapp.com/other/authorize?prompt=none",
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://discordapp.com/other/authorize?client_id=foo&prompt=none&" +
					"redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=52fdfc07-2182-454f-963f-5f0f9a621d72",
			},
		},
		{
			name: "discord provider with overridden and invalid urls",
			config: &Config{
				Name:             "discord",
				Realm:            "discord",
				Driver:           "discord",
				ClientID:         "foo",
				ClientSecret:     "bar",
				AuthorizationURL: "https://discordapp.com/other/authorize?prompt=none" + string(byte(1)),
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					Request: must(http.NewRequest(http.MethodGet, "/foo?bar=baz", nil)),
				},
			},
			shouldErr: true,
			errPhase:  "authenticate",
			err:       errors.ErrIdentityProviderConfig.WithArgs("could not parse authorization url"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			prv, err := NewIdentityProvider(tc.config, tc.logger)
			if tests.EvalErrPhaseWithLog(t, err, "initialize", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			err = prv.Configure()
			if tests.EvalErrPhaseWithLog(t, err, "configure", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			err = prv.Authenticate(&tc.request)
			if tests.EvalErrPhaseWithLog(t, err, "authenticate", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "authenticate", tc.want, tc.request.Response, msgs)
		})
	}
}
