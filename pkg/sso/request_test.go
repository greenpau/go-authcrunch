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

package sso

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestParseRequestURL(t *testing.T) {
	testcases := []struct {
		name      string
		input     *http.Request
		want      *Request
		shouldErr bool
		err       error
	}{
		{
			name: "test metadata request",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/aws/metadata.xml",
				},
			},
			want: &Request{
				ProviderName: "aws",
				Kind:         MetadataRequest,
			},
		},
		{
			name: "test role selection request",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/aws",
				},
			},
			want: &Request{
				ProviderName: "aws",
				Kind:         MenuRequest,
			},
		},
		{
			name: "test assume role request",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/aws/assume/123456789012/Administrator",
				},
			},
			want: &Request{
				ProviderName: "aws",
				Kind:         AssumeRoleRequest,
				Params:       "123456789012/Administrator",
			},
		},
		{
			name: "test malformed assume role request",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/aws/assume/",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderRequestMalformed,
		},
		{
			name: "test malformed request",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "foo/bar",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderRequestMalformed,
		},
		{
			name: "test malformed request without provider",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderRequestMalformed,
		},
		{
			name: "test malformed request with invalid params",
			input: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/apps/sso/aws/foobar",
				},
			},
			shouldErr: true,
			err:       errors.ErrSingleSignOnProviderRequestMalformed,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRequestURL(tc.input)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseRequestURL() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
