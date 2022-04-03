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

package errors

// Global security config errors.
const (
	ErrSecurityConfig                  StandardError = "security config error: %v"
	ErrMalformedDirective              StandardError = "malformed %q directive: %v"
	ErrMalformedDirectiveValue         StandardError = "malformed %q directive with %v: %v"
	ErrConfigDirectiveShort            StandardError = "the %q directive is too short: %v"
	ErrConfigDirectiveValueUnsupported StandardError = "the %q directive value of %q is unsupported"
	ErrConfigDirectiveFail             StandardError = "the %q directive with value of %q failed: %v"
	ErrPortalConfigBackendsNotFound    StandardError = "portal config has no identity providers or stores"
	ErrPortalConfigNameNotFound        StandardError = "portal config name not found"
	ErrPolicyConfigNameNotFound        StandardError = "gatekeeper policy config name not found"
)
