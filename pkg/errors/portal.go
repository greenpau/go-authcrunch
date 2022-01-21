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

// Portal errors.
const (
	ErrNewPortalLoggerNil          StandardError = "failed initializing portal: logger is nil"
	ErrNewPortalConfigNil          StandardError = "failed initializing portal: config is nil"
	ErrNewPortal                   StandardError = "failed initializing portal: %v"
	ErrPortalRegistryEntryNotFound StandardError = "authentication portal %q not found in registry"
	ErrPortalRegistryEntryExists   StandardError = "authentication portal %q already registered"
	ErrPortalUnavailable           StandardError = "portal unavailable"
)
