// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/ssh"
)

func TestRepositoryLoginDecoder(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := SchemaAt(c, "/components/schemas/LoginRequest")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"start", `{"username":"alice","realm":"local"}`, true},
		{"null defaults", `{"username":"alice","realm":"local","refresh_transport":null,"api_key":null}`, true},
		{"empty unused fields", `{"username":"alice","realm":"local","api_key":"","sandbox_id":" \t","sandbox_secret":"","challenge_kind":null,"challenge_response":"\u2003"}`, true},
		{"key with blank identity", `{"realm":"local","api_key":"key","username":"\u0085","sandbox_id":null,"sandbox_secret":"","challenge_kind":"","challenge_response":" "}`, true},
		{"all challenge fields", `{"username":"alice","realm":"local","sandbox_id":"id","sandbox_secret":"secret","challenge_kind":"password","challenge_response":"answer","api_key":""}`, true},
		{"partial challenge", `{"username":"alice","realm":"local","sandbox_id":"id"}`, false},
		{"whitespace-only username", `{"username":"\u2003","realm":"local"}`, false},
		{"whitespace-only realm", `{"username":"alice","realm":" \t"}`, false},
		{"BOM is not trimmed", `{"realm":"local","api_key":"key","username":"\ufeff"}`, false},
		{"untrimmed sandbox secret", `{"username":"alice","realm":"local","sandbox_secret":" "}`, false},
		{"untrimmed challenge kind", `{"username":"alice","realm":"local","challenge_kind":" "}`, false},
		{"key and username", `{"username":"alice","realm":"local","api_key":"key"}`, false},
		{"key native transport", `{"realm":"local","api_key":"key","refresh_transport":"body"}`, false},
		{"unknown field", `{"username":"alice","realm":"local","unknown":null}`, false},
		{"wrong field type", `{"username":"alice","realm":"local","refresh_transport":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/login", strings.NewReader(tc.body))
			_, parseErr := apiauth.ParseAuthRequest(t.Context(), httptest.NewRecorder(), r)
			var value any
			if err := json.Unmarshal([]byte(tc.body), &value); err != nil {
				t.Fatal(err)
			}
			if (parseErr == nil) != tc.valid || (schema.Validate(value) == nil) != tc.valid {
				t.Fatal("schema and selected login decoder disagree")
			}
		})
	}
	base := `{"username":"alice","realm":"local"}`
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"exact reader limit", strings.Repeat(" ", 1024-len(base)) + base, true},
		{"over reader limit", strings.Repeat(" ", 1025-len(base)) + base, false},
		{"unread second value", base + `{"unknown":true}`, true},
		{"unread large suffix", base + strings.Repeat("x", 2048), true},
		{"case aliases and null", `{"USERNAME":"wrong","username":"alice","USERNAME":null,"REALM":"local"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/login", strings.NewReader(tc.body))
			value, err := apiauth.ParseAuthRequest(t.Context(), httptest.NewRecorder(), r)
			if (err == nil) != tc.valid {
				t.Fatal("login reader/lexical contract changed")
			}
			if err == nil && (value.Username != "alice" || value.Realm != "local") {
				t.Fatal("decoded canonical identity changed")
			}
		})
	}
}

func TestRepositoryProfilePublicKeys(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := SchemaAt(c, "/components/schemas/ProfilePublicKeyRecord")
	if err != nil {
		t.Fatal(err)
	}
	check := func(key *identity.PublicKey) {
		t.Helper()
		value, err := jsonValue(key)
		if err != nil || schema.Validate(value) != nil {
			t.Fatal("public-key serializer and schema disagree (value withheld)")
		}
		fields := value.(map[string]any)
		fields["id"] = "not-a-record-id"
		if schema.Validate(fields) == nil {
			t.Fatal("invalid key identifier accepted")
		}
		fields["id"] = key.ID
		fields["fingerprint"] = "not-a-fingerprint"
		if schema.Validate(fields) == nil {
			t.Fatal("invalid key fingerprint accepted")
		}
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sshText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))) + " inline@example.test"
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&private.PublicKey)}))
	for name, payload := range map[string]string{"authorized key": sshText, "PKCS1": pemText} {
		t.Run(name, func(t *testing.T) {
			key, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "ssh", Payload: payload, Comment: "upload title"}})
			if err != nil {
				t.Fatal(err)
			}
			check(key)
			if name == "authorized key" {
				block, _ := pem.Decode([]byte(key.Payload))
				if block == nil || block.Type != "RSA PUBLIC KEY" || key.Comment != "inline@example.test" {
					t.Fatal("SSH stored metadata changed")
				}
				if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
					t.Fatal("stored authorized key is no longer SPKI")
				}
				if _, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "ssh", Payload: key.Payload}}); err == nil {
					t.Fatal("historical mislabeled payload now round-trips; update its contract")
				}
			}
		})
	}
	// Duplicate comparison includes MD5, so the different SHA256 prefix cannot
	// make the same RSA key in two encodings into two records.
	owner := &identity.User{}
	if err := owner.AddPublicKey(&requests.Request{Key: requests.Key{Usage: "ssh", Payload: sshText}}); err != nil {
		t.Fatal(err)
	}
	if err := owner.AddPublicKey(&requests.Request{Key: requests.Key{Usage: "ssh", Payload: pemText}}); err == nil {
		t.Fatal("cross-format duplicate accepted")
	}
	legacy, err := os.ReadFile("../../testdata/gpg/linux_gpg_pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	pgp, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: string(legacy)}})
	if err != nil {
		t.Fatal(err)
	}
	check(pgp)
	concatenated, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: string(legacy) + "\n" + string(legacy)}})
	if err != nil || concatenated.Fingerprint != pgp.Fingerprint {
		t.Fatal("first-armored-block parsing changed")
	}
	check(concatenated)
	for _, v6 := range []bool{false, true} {
		entity, err := openpgp.NewEntity("Fixture", "", "fixture@example.test", &packet.Config{RSABits: 2048, V6Keys: v6})
		if err != nil {
			t.Fatal("cannot generate synthetic OpenPGP key")
		}
		var encoded bytes.Buffer
		writer, err := armor.Encode(&encoded, openpgp.PublicKeyType, nil)
		if err != nil || entity.Serialize(writer) != nil || writer.Close() != nil {
			t.Fatal("cannot armor synthetic public key")
		}
		key, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: encoded.String()}})
		if err != nil {
			t.Fatal("selected parser rejected synthetic OpenPGP key")
		}
		check(key)
		if v6 && len(key.Fingerprint) != 64 || !v6 && len(key.Fingerprint) != 40 {
			t.Fatal("OpenPGP version/fingerprint length changed")
		}
		if !v6 {
			if err := owner.AddPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: encoded.String()}}); err != nil {
				t.Fatal(err)
			}
		} else if err := owner.AddPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: encoded.String()}}); err == nil {
			t.Fatal("empty MD5 comparison no longer rejects distinct same-algorithm OpenPGP keys")
		}
	}
	modern, err := openpgp.NewEntity("Fixture", "", "fixture@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal("cannot generate synthetic EdDSA OpenPGP key")
	}
	var encoded bytes.Buffer
	writer, err := armor.Encode(&encoded, openpgp.PublicKeyType, nil)
	if err != nil || modern.Serialize(writer) != nil || writer.Close() != nil {
		t.Fatal("cannot armor synthetic EdDSA public key")
	}
	if parsed, err := openpgp.ReadArmoredKeyRing(strings.NewReader(encoded.String())); err != nil || len(parsed) != 1 {
		t.Fatal("unsupported-algorithm fixture must be valid OpenPGP")
	}
	if _, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: encoded.String()}}); err == nil || !strings.Contains(err.Error(), "unsupported public key algo") {
		t.Fatal("selected metadata parser no longer rejects valid EdDSA primary keys")
	}
	t.Run("OpenPGP entity admission", func(t *testing.T) {
		entity, err := openpgp.NewEntity("Fixture", "", "fixture@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveNistP256})
		if err != nil {
			t.Fatal("cannot generate synthetic ECDSA entity")
		}
		armorPackets := func(write func(io.Writer) error) string {
			t.Helper()
			var buf bytes.Buffer
			w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
			if err != nil || write(w) != nil || w.Close() != nil {
				t.Fatal("cannot serialize synthetic packets")
			}
			return buf.String()
		}
		rsaEncryption := packet.NewRSAPublicKey(entity.PrimaryKey.CreationTime, &private.PublicKey)
		rsaEncryption.PubKeyAlgo = packet.PubKeyAlgoRSAEncryptOnly
		ecdhPrimary := *entity.Subkeys[0].PublicKey
		ecdhPrimary.IsSubkey = false
		tampered := *entity
		tampered.Identities = make(map[string]*openpgp.Identity)
		for name, id := range entity.Identities {
			copy := *id
			copy.UserId = packet.NewUserId("Changed", "", "changed@example.test")
			tampered.Identities[name] = &copy
		}
		for name, primary := range map[string]*packet.PublicKey{"RSA encryption only": rsaEncryption, "ECDH": &ecdhPrimary} {
			t.Run(name, func(t *testing.T) {
				payload := armorPackets(primary.Serialize)
				_, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: payload}})
				if err == nil || !strings.Contains(err.Error(), "primary key cannot be used for signatures") {
					t.Fatal("encryption-only primary did not fail at the entity reader")
				}
			})
		}
		for _, tc := range []struct {
			name  string
			write func(io.Writer) error
			valid bool
		}{
			{"ECDSA public", entity.Serialize, true},
			{"invalid identity self-signature", tampered.Serialize, false},
			{"two decoded entities", func(w io.Writer) error {
				if err := entity.Serialize(w); err != nil {
					return err
				}
				return entity.Serialize(w)
			}, false},
			{"unsupported entity skipped", func(w io.Writer) error {
				if err := rsaEncryption.Serialize(w); err != nil {
					return err
				}
				return entity.Serialize(w)
			}, true},
			{"secret packets in public armor", func(w io.Writer) error { return entity.SerializePrivateWithoutSigning(w, nil) }, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				payload := armorPackets(tc.write)
				key, err := identity.NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: payload}})
				if (err == nil) != tc.valid {
					t.Fatal("OpenPGP entity admission changed")
				}
				if key != nil {
					check(key)
				}
				if tc.name == "secret packets in public armor" {
					// Synthetic secrets stay in memory. An armor label is not a packet filter.
					parsed, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.Payload))
					if err != nil || len(parsed) != 1 || parsed[0].PrivateKey == nil {
						t.Fatal("stored packet-kind contract changed")
					}
				}
			})
		}
	})
}
