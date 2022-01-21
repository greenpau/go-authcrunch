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

// Gatekeeper errors.
const (
	ErrNewGatekeeperLoggerNil          StandardError = "failed initializing gatekeeper: logger is nil"
	ErrNewGatekeeperConfigNil          StandardError = "failed initializing gatekeeper: config is nil"
	ErrNewGatekeeper                   StandardError = "failed initializing gatekeeper: %v"
	ErrGatekeeperRegistryEntryNotFound StandardError = "gatekeeper %q not found in registry"
	ErrGatekeeperRegistryEntryExists   StandardError = "gatekeeper %q already registered"
	ErrGatekeeperUnavailable           StandardError = "gatekeeper unavailable"
)
