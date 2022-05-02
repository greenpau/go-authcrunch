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
