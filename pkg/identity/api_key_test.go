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

package identity

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestNewAPIKey(t *testing.T) {
	testcases := []struct {
		name      string
		req       *requests.Request
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test api key",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "api",
					Comment: "jsmith-api-key",
					Payload: GetRandomStringFromRange(54, 72),
				},
			},
			want: map[string]interface{}{
				"usage":    "api",
				"comment":  "jsmith-api-key",
				"disabled": false,
			},
		},
		{
			name: "test disabled api key",
			req: &requests.Request{
				Key: requests.Key{
					Usage:    "api",
					Comment:  "jsmith-api-key",
					Disabled: true,
					Payload:  GetRandomStringFromRange(54, 72),
				},
			},
			want: map[string]interface{}{
				"usage":    "api",
				"comment":  "jsmith-api-key",
				"disabled": true,
			},
		},
		{
			name: "test api key with empty payload",
			req: &requests.Request{
				Key: requests.Key{
					Usage:    "api",
					Comment:  "jsmith-api-key",
					Disabled: true,
				},
			},
			shouldErr: true,
			err:       errors.ErrAPIKeyPayloadEmpty,
		},
		{
			name: "test api key with empty payload",
			req: &requests.Request{
				Key: requests.Key{
					Usage:    "api",
					Comment:  "jsmith-api-key",
					Disabled: true,
				},
			},
			shouldErr: true,
			err:       errors.ErrAPIKeyPayloadEmpty,
		},
		{
			name: "test api key with empty usage",
			req: &requests.Request{
				Key: requests.Key{
					Comment:  "jsmith-api-key",
					Payload:  GetRandomStringFromRange(54, 72),
					Disabled: true,
				},
			},
			shouldErr: true,
			err:       errors.ErrAPIKeyUsageEmpty,
		},
		{
			name: "test api key with unsupported usage",
			req: &requests.Request{
				Key: requests.Key{
					Usage:    "foo",
					Comment:  "jsmith-api-key",
					Payload:  GetRandomStringFromRange(54, 72),
					Disabled: true,
				},
			},
			shouldErr: true,
			err:       errors.ErrAPIKeyUsageUnsupported.WithArgs("foo"),
		},
		{
			name: "test api key with empty comment",
			req: &requests.Request{
				Key: requests.Key{
					Usage:    "api",
					Payload:  GetRandomStringFromRange(54, 72),
					Disabled: true,
				},
			},
			shouldErr: true,
			err:       errors.ErrAPIKeyCommentEmpty,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.req.Key.Payload != "" {
				tc.req.Response.Payload = tc.req.Key.Payload
				hk, err := NewPassword(tc.req.Key.Payload)
				if err != nil {
					t.Fatalf("unexpected password generation error: %s", err)
				}
				tc.req.Key.Payload = hk.Hash
			}
			key, err := NewAPIKey(tc.req)
			if tests.EvalErrWithLog(t, err, "new api key", tc.shouldErr, tc.err, msgs) {
				return
			}

			got := make(map[string]interface{})
			got["usage"] = key.Usage
			got["comment"] = key.Comment
			got["disabled"] = key.Disabled

			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)
			key.Disable()

			bundle := NewAPIKeyBundle()
			bundle.Add(key)
			bundle.Get()
			bundle.Size()
		})
	}
}
