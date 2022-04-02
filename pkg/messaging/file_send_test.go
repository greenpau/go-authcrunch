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

package messaging

import (
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
)

func TestFileProviderSend(t *testing.T) {
	tmpDir, err := tests.TempDir("TestFileProviderSend")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir += "/inbox"
	// t.Logf("Temp dir: %s", tmpDir)

	testcases := []struct {
		name      string
		provider  *FileProvider
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test sending notification",
			provider: &FileProvider{
				Name:    "default",
				RootDir: tmpDir,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.provider.Validate()
			if err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}

			err = tc.provider.Send(&FileProviderSendInput{
				Subject:    "foo",
				Body:       "foobar",
				Recipients: []string{"root@localhost"},
			})

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
		})
	}
}
