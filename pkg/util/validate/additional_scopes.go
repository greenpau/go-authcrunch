package validate

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"regexp"
)

var pattern = regexp.MustCompile("^[\\w|\\s]+$")

// AdditionalScopes verifies if the provided additional_scopes argument is valid
func AdditionalScopes(additionalScopes string) error {
	if !pattern.MatchString(additionalScopes) {
		return errors.ErrInvalidAdditionalScopes
	}
	return nil
}
