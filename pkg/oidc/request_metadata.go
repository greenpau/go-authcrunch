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

package oidc

import (
	"context"
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// RequestMetadata is a snapshot of the current HTTP request for identity policy
// checks. URL includes the path but no query, fragment, or credentials. Forwarded
// header normalization remains the embedding server's responsibility.
type RequestMetadata struct {
	URL, SourceAddress string `json:"-" xml:"-" yaml:"-"`
}

type requestMetadataContextKey struct{}

// RequestMetadataFromContext returns the current request's metadata inside an
// IdentityVerifier callback. HandleHTTP, ServeHTTP, and CompleteLogin supply it.
// It describes this operation, not the original browser's login, and is never
// retained in session evidence. The returned value is an independent snapshot.
func RequestMetadataFromContext(ctx context.Context) (RequestMetadata, bool) {
	metadata, ok := ctx.Value(requestMetadataContextKey{}).(RequestMetadata)
	return metadata, ok
}

func withRequestMetadata(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, requestMetadataContextKey{}, RequestMetadata{
		URL: util.GetCurrentURL(r), SourceAddress: addrutil.GetSourceAddress(r),
	})
}
