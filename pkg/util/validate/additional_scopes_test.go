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

package validate

import (
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestAdditionalScopes(t *testing.T) {
	var testcases = []struct {
		name             string
		additionalScopes string
		shouldErr        bool
		err              error
	}{
		{
			name:             "doesn't return an error if the provided additional_scopes are in a valid format",
			additionalScopes: "email profile orders",
			shouldErr:        false,
			err:              nil,
		},
		{
			name:             "doesn't return an error if the provided additional_scopes is only one",
			additionalScopes: "email",
			shouldErr:        false,
			err:              nil,
		},
		{
			name:             "returns an error if the provided additional_scopes have invalid characters #1",
			additionalScopes: "<e_mail>",
			shouldErr:        true,
			err:              errors.ErrInvalidAdditionalScopes,
		},
		{
			name:             "returns an error if the provided additional_scopes have invalid characters #2",
			additionalScopes: "&e_mail?",
			shouldErr:        true,
			err:              errors.ErrInvalidAdditionalScopes,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := AdditionalScopes(tc.additionalScopes)

			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, []string{}) {
				return
			}
		})
	}
}
