package util

import (
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
)

func TestUrlSanitization(t *testing.T) {
	t.Run("should sanitize  url if its malformed in a way that is intended to cause a XSS", func(t *testing.T) {
		maliciousUrl := "https://www.google.com/search?hl=en&q=testing'\"()&%<acx><ScRiPt >alert(9854)</ScRiPt>"

		sanitizedUrl := SanitizeUrlForInvalidCharacters(maliciousUrl)

		tests.EvalObjectsWithLog(t, "sanitized url", "https://www.google.com/search?hl=en%26q=testing%27%22()%26%%3Cacx%3E%3CScRiPt %3Ealert(9854)%3C/ScRiPt%3E", sanitizedUrl, []string{})
	})
}
