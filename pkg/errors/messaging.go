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

// Messaging Errors
const (
	ErrMessagingAddProviderConfigType       StandardError = "messaging provider config %T is unsupported"
	ErrMessagingProviderKeyValueEmpty       StandardError = "messaging provider config %q key is empty"
	ErrMessagingProviderInvalidTemplate     StandardError = "messaging provider config contains unsupported %q template"
	ErrMessagingProviderProtocolUnsupported StandardError = "messaging provider config %q protocol unsupported"

	ErrMessagingProviderCredentialsWithPasswordless StandardError = "messaging provider config is both passwordless and has credentials"
	ErrMessagingProviderAuthUnsupported             StandardError = "messaging provider does not support AUTH extension"

	ErrMessagingProviderSend StandardError = "messaging provider send error: %v"
	ErrMessagingProviderDir  StandardError = "messaging provider file dir error: %s: %v"

	ErrMessagingMalformedInstruction               StandardError = "malformed messaging provider instruction: %s: %q"
	ErrMessagingMalformedInstructionUnsupportedKey StandardError = "malformed messaging provider instruction: unsupported key: %q"
	ErrMessagingMalformedInstructionBadSyntax      StandardError = "malformed messaging provider instruction: bad syntax: %q"
	ErrMessagingMalformedInstructionKindMismatch   StandardError = "malformed messaging provider instruction: kind mismatch, want: %q, got %q"
	ErrMessagingMalformedInstructionThrown         StandardError = "malformed messaging provider instruction with error: %v: %q"
	ErrMessagingUnsupportedKind                    StandardError = "unsupported messaging provider kind: %s"
	ErrMessagingConfigEmpty                        StandardError = "messaging provider config is empty"
)
