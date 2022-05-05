package validate

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"regexp"
)

// AdditionalScopes verifies if the provided additional_scopes argument is valid
func AdditionalScopes(additionalScopes string) error {
	fmt.Println(additionalScopes)
	compile, _ := regexp.Compile("^[\\w|\\s]+$")
	match := compile.MatchString(additionalScopes)
	if match == false {
		return errors.ErrInvalidAdditionalScopes
	}
	return nil
}
