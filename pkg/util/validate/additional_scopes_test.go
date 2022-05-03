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
			additionalScopes: "email%20profile%20orders",
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
			name:             "returns an error if the provided additional_scopes are in a invalid format",
			additionalScopes: "email profile orders",
			shouldErr:        true,
			err:              errors.ErrInvalidAdditionalScopes,
		},
		{
			name:             "returns an error if the provided additional_scopes contains underscores",
			additionalScopes: "e_mail%20profile%20orders",
			shouldErr:        false,
			err:              nil,
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
