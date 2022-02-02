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

// Notification Errors
const (
	ErrNotifyRequestDataNil                   StandardError = "notification request has no data"
	ErrNotifyRequestTemplateUnsupported       StandardError = "notification request template %q is unsupported"
	ErrNotifyRequestFieldNotFound             StandardError = "notification request is missing required %q field"
	ErrNotifyRequestLangUnsupported           StandardError = "notification request %q language is unsupported"
	ErrNotifyRequestEmailProviderNotFound     StandardError = "notification request %q email provider not found"
	ErrNotifyRequestEmailProviderCredNotFound StandardError = "notification request %q email provider credentials not found"
	ErrNotifyRequestCredNotFound              StandardError = "notification request %q email provider %q credentials not found"
	ErrNotifyRequestProviderTypeUnsupported   StandardError = "notification request %q email provider type %q is unsupported"
	ErrNotifyRequestEmail                     StandardError = "notification request via %q email provider failed: %v"
	ErrNotifyRequestMessagingNil              StandardError = "notification request via %q email provider has no access to messaging"
	ErrNotifyRequestCredNil                   StandardError = "notification request via %q email provider has no access to credentials"
)
