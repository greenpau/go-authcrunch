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

package identity

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/ssh"
)

func readPEMFile(fp string) string {
	var buffer bytes.Buffer
	fileHandle, err := os.Open(fp)
	if err != nil {
		panic(err)
	}
	defer fileHandle.Close()
	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		buffer.WriteString(strings.TrimSpace(line) + "\n")
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return buffer.String()
}

func getPublicKey(t *testing.T, pk *rsa.PrivateKey, keyType string) string {
	switch keyType {
	case "openssh":
		// Create OpenSSH formatted string
		pubKeyOpenSSH, err := ssh.NewPublicKey(pk.Public())
		if err != nil {
			t.Fatalf("failed creating openssh key: %v", err)
		}
		authorizedKeyBytes := ssh.MarshalAuthorizedKey(pubKeyOpenSSH)
		return string(authorizedKeyBytes)
	case "rsa":
		switch pubKey := pk.Public().(type) {
		case *rsa.PublicKey:
			pubKeyBytes := x509.MarshalPKCS1PublicKey(pubKey)
			// Create PEM encoded string
			pubKeyEncoded := pem.EncodeToMemory(
				&pem.Block{
					Type:  "RSA PUBLIC KEY",
					Bytes: pubKeyBytes,
				},
			)
			return string(pubKeyEncoded)
		default:
			t.Fatalf("unsupported key type: %s", keyType)
		}
	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}
	return ""
}

func TestNewPublicKey(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating private key: %v", err)
	}
	if err := pk.Validate(); err != nil {
		t.Fatalf("failed validating private key: %v", err)
	}
	pkb := x509.MarshalPKCS1PrivateKey(pk)
	pkm := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pkb,
		},
	)
	// t.Logf("private rsa key:\n%s", string(pkm))

	testcases := []struct {
		name      string
		req       *requests.Request
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "test ssh rsa key",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "ssh",
					Comment: "jsmith@outlook.com",
					Payload: "rsa",
				},
			},
			want: map[string]interface{}{
				"usage":   "ssh",
				"type":    "ssh-rsa",
				"comment": "jsmith@outlook.com",
			},
		},
		{
			name: "test openssh key",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "ssh",
					Comment: "jsmith@outlook.com",
					Payload: "openssh",
				},
			},
			want: map[string]interface{}{
				"usage":   "ssh",
				"type":    "ssh-rsa",
				"comment": "jsmith@outlook.com",
			},
		},
		{
			name: "test unsupported public key usage",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "foobar",
					Payload: "-----BEGIN RSA PUBLIC KEY-----",
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyInvalidUsage.WithArgs("foobar"),
		},
		{
			name: "test empty public key payload",
			req: &requests.Request{
				Key: requests.Key{
					Usage: "ssh",
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyEmptyPayload,
		},
		{
			name: "test public key payload and usage mismatch",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "gpg",
					Payload: "-----BEGIN RSA PUBLIC KEY-----",
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyUsagePayloadMismatch.WithArgs("gpg"),
		},
		{
			name: "test public key block type error",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "ssh",
					Payload: "-----BEGIN RSA PUBLIC KEY-----",
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyBlockType.WithArgs(""),
		},
		{
			name: "test public key unexpected block type",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "ssh",
					Payload: strings.Replace(string(pkm), "PRIVATE", "PUBLIC", 1),
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyBlockType.WithArgs(""),
		},
		{
			name: "test gpg public key without end block",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "gpg",
					Comment: "jsmith@outlook.com",
					Payload: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
				},
			},
			shouldErr: true,
			err:       errors.ErrPublicKeyParse.WithArgs("END PGP PUBLIC KEY BLOCK not found"),
		},
		{
			name: "test gpg public key",
			req: &requests.Request{
				Key: requests.Key{
					Usage:   "gpg",
					Payload: readPEMFile("../../testdata/gpg/linux_gpg_pub.pem"),
				},
			},
			want: map[string]interface{}{
				"usage":   "gpg",
				"type":    "dsa",
				"comment": "Google, Inc. Linux Package Signing Key <linux-packages-keymaster@google.com>, algo DSA, created 2007-03-08 20:17:10 +0000 UTC",
				"id":      "a040830f7fac5991",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			if tc.req.Key.Usage == "ssh" {
				msgs = append(msgs, fmt.Sprintf("private rsa key:\n%s", string(pkm)))
			} else {
				msgs = append(msgs, fmt.Sprintf("payload:\n%s", string(tc.req.Key.Payload)))
			}

			if tc.req.Key.Payload == "rsa" || tc.req.Key.Payload == "openssh" {
				tc.req.Key.Payload = getPublicKey(t, pk, tc.req.Key.Payload)
			}
			// t.Logf("public key:\n%s", tc.req.Key.Payload)

			key, err := NewPublicKey(tc.req)
			if tests.EvalErrWithLog(t, err, "new public key", tc.shouldErr, tc.err, msgs) {
				return
			}
			// t.Logf("%v", key)

			got := make(map[string]interface{})
			got["type"] = key.Type
			got["usage"] = key.Usage
			got["comment"] = key.Comment
			if key.Usage == "gpg" {
				got["id"] = key.ID
			}
			tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)

			bundle := NewPublicKeyBundle()
			bundle.Add(key)
			bundle.Get()
			key.Disable()
		})
	}
}
