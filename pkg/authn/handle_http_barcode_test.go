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

package authn

import (
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMFABarcodeEncoding(t *testing.T) {
	const want = "otpauth://totp/Tests:user@example.test?secret=AAA&period=60"
	for _, tc := range []struct {
		name, encoded string
		status        int
	}{
		{"legacy", "b3RwYXV0aDovL3RvdHAvVGVzdHM6dXNlckBleGFtcGxlLnRlc3Q/c2VjcmV0PUFBQSZwZXJpb2Q9NjA=", http.StatusOK},
		{"canonical", "b3RwYXV0aDovL3RvdHAvVGVzdHM6dXNlckBleGFtcGxlLnRlc3Q_c2VjcmV0PUFBQSZwZXJpb2Q9NjA", http.StatusOK},
		{"invalid", "not%base64!", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeBarcodeURI(tc.encoded)
			if tc.status == http.StatusOK && (err != nil || string(decoded) != want) {
				t.Fatal("QR encoding changed the enrollment URI")
			}
			if tc.status != http.StatusOK && err == nil {
				t.Fatal("malformed QR encoding accepted")
			}
			recorder := httptest.NewRecorder()
			portal := &Portal{}
			if err := portal.handleHTTPSandboxMfaBarcode(t.Context(), recorder, nil, tc.encoded+".png"); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != tc.status {
				t.Fatalf("status %d, want %d", recorder.Code, tc.status)
			}
			if tc.status != http.StatusOK {
				return
			}
			if recorder.Header().Get("Content-Type") != "image/png" {
				t.Fatal("QR content type changed")
			}
			image, err := png.DecodeConfig(recorder.Body)
			if err != nil || image.Width != 256 || image.Height != 256 {
				t.Fatal("QR endpoint did not return a scannable-size PNG")
			}
		})
	}
}
