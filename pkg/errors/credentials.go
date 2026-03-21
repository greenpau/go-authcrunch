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

// Credentials Errors
const (
	ErrCredAddConfigType                      StandardError = "credential config %T is unsupported"
	ErrCredKeyValueEmpty                      StandardError = "credential config %q key is empty"
	ErrCredMalformedInstruction               StandardError = "malformed credential instruction: %s: %q"
	ErrCredMalformedInstructionUnsupportedKey StandardError = "malformed credential instruction: unsupported key: %q"
	ErrCredMalformedInstructionBadSyntax      StandardError = "malformed credential instruction: bad syntax: %q"
	ErrCredMalformedInstructionKindMismatch   StandardError = "malformed credential instruction: kind mismatch, want: %q, got %q"
	ErrCredMalformedInstructionThrown         StandardError = "malformed credential instruction with error: %v: %q"
	ErrCredUnsupportedKind                    StandardError = "unsupported credential kind: %s"
	ErrCredConfigEmpty                        StandardError = "credential config is empty"
)
