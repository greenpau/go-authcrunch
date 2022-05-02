package util

import (
	"net/url"
	"regexp"
)

// SanitizeUrlForInvalidCharacters escapes some invalid characters than can allow for Cross Site Scripting
func SanitizeUrlForInvalidCharacters(urlToSanitize string) string {
	r := regexp.MustCompile("[&|<|>|\"|']")
	return r.ReplaceAllStringFunc(urlToSanitize, func(s string) string {
		return url.QueryEscape(s)
	})
}
