package cfg

import (
	"github.com/greenpau/aaasf/pkg/errors"
)

const (
	// ReplErrStr represents error replacement string.
	ReplErrStr string = "ERROR_REPLACEMENT"
)

// ArgRule represents a rules that applies to an arguments passed
// in a config.
type ArgRule struct {
	Min int `json:"min,omitempty" xml:"min,omitempty" yaml:"min,omitempty"`
	Max int `json:"max,omitempty" xml:"max,omitempty" yaml:"max,omitempty"`
}

// ValidateArg performs argument validation.
func ValidateArg(rules map[string]*ArgRule, k string, v []string) error {
	r, exists := rules[k]
	if !exists {
		return nil
	}
	if r.Min > len(v) {
		return errors.ErrValidateArgTooFew.WithArgs(k, len(v), r.Min)
	}
	if r.Max < len(v) {
		return errors.ErrValidateArgTooMany.WithArgs(k, len(v), r.Min)
	}
	return nil
}

// FindStrArr returns true if a string found in a slice.
func FindStrArr(arr []string, s string) bool {
	for _, x := range arr {
		if x == s {
			return true
		}
	}
	return false
}
