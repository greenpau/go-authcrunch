// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/openapi"
)

var openAPIJourneyMu sync.Mutex
var openAPIJourneyValidator openAPIResponseValidator
var openAPIJourneyPaths map[string]map[string]any
var openAPIJourneyCoverage = map[string]int{}

// Explicit contract journeys reuse independent, complete native HTTP tests.
// Ordinary feature tests do not depend on documentation assets or this hook.
func openAPIJourneyResponse(t *testing.T, issuer string, target *url.URL, method string, status int, headers http.Header, body []byte) {
	t.Helper()
	if !strings.HasPrefix(t.Name(), "TestE2EOpenAPIContractNativeJourneys/") {
		return
	}
	origin, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != origin.Host || !strings.HasPrefix(target.Path, origin.Path+"/") {
		return
	}
	path := strings.TrimPrefix(target.Path, origin.Path)
	openAPIJourneyMu.Lock()
	defer openAPIJourneyMu.Unlock()
	if openAPIJourneyValidator == nil {
		openAPIJourneyValidator, _ = openAPIContractValidators(t)
		data, err := openapi.Bundle("../../assets/openapi/content")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Paths map[string]map[string]any `json:"paths"`
		}
		if err = json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		openAPIJourneyPaths = doc.Paths
	}
	// Check literal paths before templates, particularly the two OAuth modes.
	paths := make([]string, 0, len(openAPIJourneyPaths))
	for p := range openAPIJourneyPaths {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return strings.Count(paths[i], "{") < strings.Count(paths[j], "{") })
	for _, template := range paths {
		pattern := regexp.QuoteMeta(template)
		pattern = regexp.MustCompile(`\\\{[^{}]*\\\}`).ReplaceAllString(pattern, `[^/]+`)
		if !regexp.MustCompile("^" + pattern + "$").MatchString(path) {
			continue
		}
		item := openAPIJourneyPaths[template]
		documented := strings.ToLower(method)
		if item[documented] == nil {
			// Unsupported methods are represented on the implemented operation's
			// documented rejection, rather than invented callable operations.
			if item["post"] != nil {
				documented = "post"
			} else if item["get"] != nil {
				documented = "get"
			} else {
				return
			}
		}
		openAPIJourneyValidator(t, template, strings.ToUpper(documented), status, headers, body)
		openAPIJourneyCoverage[strings.ToUpper(documented)+" "+template]++
		return
	}
}

func TestE2EOpenAPIContractNativeJourneys(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"oidc_consent", TestE2EOIDCProviderBrowserConsent},
		{"oidc_pkce", TestE2EOIDCClientBindingAndPKCE},
		{"oidc_errors", TestE2EOIDCProtocolErrors},
		{"oidc_request_objects", TestE2EOIDCRequestObjects},
		{"oidc_claims_refresh", TestE2EOIDCClaimsAndRefresh},
		{"oidc_revocation", TestE2EOIDCRefreshRevocation},
		{"oidc_cors", TestE2EOIDCBrowserClientCORS},
		{"cross_device", TestE2ECrossDeviceLogin},
		{"cross_device_rejections", TestE2ECrossDeviceHTTPBoundaries},
		{"cross_device_oauth", TestE2ECrossDeviceOAuth},
		{"cross_device_saml", TestE2ECrossDeviceSAML},
		{"refresh_logout", TestE2ECrossDeviceRefreshLogout},
		{"refresh_preconditions", TestE2ERefreshSessionPrecondition},
		{"webauthn", TestE2EWebAuthnAssertionOriginBoundToTLSPortal},
	} {
		t.Run(tc.name, tc.run)
	}
	openAPIJourneyMu.Lock()
	defer openAPIJourneyMu.Unlock()
	for _, operation := range []string{"POST /login", "GET /oidc/authorize", "POST /oidc/token", "GET /oidc/userinfo", "POST /oidc/revoke", "POST /cross-device/start", "POST /cross-device/poll", "POST /api/refresh_token", "POST /api/logout"} {
		if openAPIJourneyCoverage[operation] == 0 {
			t.Errorf("native journey did not validate %s", operation)
		}
	}
	t.Logf("validated %d native HTTP operations", len(openAPIJourneyCoverage))

}
