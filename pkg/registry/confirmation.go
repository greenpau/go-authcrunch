// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package registry

import "context"

// ConfirmationProvider optionally replaces the portal's legacy read/delete/AddUser
// sequence. Success means a confirmed, enabled account is durably available for
// login. The provider owns expiry, attempt limits, single use and recoverable
// creation, and must withhold success on storage failure. The portal redirects to
// login without executing legacy AddUser or administrative approval notifications.
// Failure must not expose credentials or raw confirmation codes.
type ConfirmationProvider interface {
	ConfirmRegistration(context.Context, string, string) error
}
