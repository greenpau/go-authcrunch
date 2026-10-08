// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

func testOpenAPILoginAndProfile(t *testing.T, validate openAPIResponseValidator, component func(*testing.T, string, any)) {
	f := newOpenAPIPortalFixture(t, "/auth", "enable admin api", true)
	t.Run("login_decoder", func(t *testing.T) {
		base := `{"username":"keymember","realm":"local"}`
		for _, tc := range []struct {
			name, body, media string
			status            int
		}{
			{"canonical", base, "application/json", 200},
			{"null and empty fields", `{"username":"keymember","realm":"local","refresh_transport":null,"api_key":null,"sandbox_id":"\u2003","sandbox_secret":"","challenge_kind":null,"challenge_response":" "}`, "application/json", 200},
			{"field case and duplicate null", `{"USERNAME":"wrong","username":"keymember","username":null,"REALM":"local"}`, "application/json", 200},
			{"trailing second value", base + `{"unknown":true}`, "application/json", 200},
			{"large unread suffix", base + strings.Repeat("x", 2048), "application/json", 200},
			{"exact reader limit", strings.Repeat(" ", 1024-len(base)) + base, "application/json", 200},
			{"over reader limit", strings.Repeat(" ", 1025-len(base)) + base, "application/json", 400},
			{"media not enforced", base, "text/plain", 200},
			{"unknown field", `{"username":"keymember","realm":"local","unknown":null}`, "application/json", 400},
			{"partial challenge", `{"username":"keymember","realm":"local","sandbox_secret":" "}`, "application/json", 400},
			{"blank identity", `{"username":"\u2003","realm":"local"}`, "application/json", 400},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, body := f.request(t, "POST", "/login", "", tc.body, tc.status, map[string][]string{"Content-Type": {tc.media}})
				validate(t, "/login", "POST", tc.status, h, body)
			})
		}
		// Complete a real challenge returned by a request with null defaults.
		h, body := f.request(t, "POST", "/login", "", `{"username":"keymember","realm":"local","refresh_transport":null}`, 200)
		validate(t, "/login", "POST", 200, h, body)
		var checkpoint map[string]any
		if json.Unmarshal(body, &checkpoint) != nil {
			t.Fatal("invalid checkpoint")
		}
		checkpoint["username"], checkpoint["realm"] = "keymember", "local"
		checkpoint["challenge_kind"], checkpoint["challenge_response"] = checkpoint["next_challenge"], tests.TestPwd1
		checkpoint["api_key"], checkpoint["refresh_transport"] = nil, nil
		delete(checkpoint, "next_challenge")
		request, err := json.Marshal(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		component(t, "LoginRequest", checkpoint)
		h, body = f.request(t, "POST", "/login", "", string(request), 200)
		validate(t, "/login", "POST", 200, h, body)
		var issued map[string]any
		if json.Unmarshal(body, &issued) != nil || issued["authenticated"] != true {
			t.Fatal("null-default challenge did not complete authentication")
		}
	})
	t.Run("basic_admission", func(t *testing.T) {
		encode := func(value string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(value)) }
		valid := encode("keymember:" + tests.TestPwd1)
		wrong := encode("keymember:wrong-password")
		for _, tc := range []struct {
			name, realm string
			headers     []string
			status      int
			challenge   bool
		}{
			{"missing", "local", nil, 401, true},
			{"unsupported mixed case", "local", []string{strings.Replace(valid, "Basic", "BaSiC", 1)}, 401, true},
			{"bad base64", "local", []string{"Basic %%%"}, 400, false},
			{"missing colon", "local", []string{encode("keymember")}, 400, false},
			{"empty username", "local", []string{encode(":" + tests.TestPwd1)}, 500, false},
			{"empty password", "local", []string{encode("keymember:")}, 500, false},
			{"wrong password", "local", []string{wrong}, 401, false},
			{"raw username", "local", []string{encode("key%6dember:" + tests.TestPwd1)}, 401, false},
			{"realm override", "absent", []string{valid + ", Realm=local"}, 303, false},
			{"quoted realm is literal", "local", []string{valid + `, Realm="local"`}, 400, false},
			{"later segment wins", "local", []string{wrong + ", " + valid}, 303, false},
			{"first header wins", "local", []string{valid, wrong}, 303, false},
			{"lowercase basic", "local", []string{strings.Replace(valid, "Basic", "basic", 1)}, 303, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				status, h, body := registrationHTTP(t, f.client, "GET", f.base+f.mount+"/basic/login/"+tc.realm, nil, map[string][]string{"Accept": {"text/html"}, "Authorization": tc.headers})
				if status != tc.status {
					t.Fatalf("Basic status %d, want %d", status, tc.status)
				}
				validate(t, "/basic/login/{realm}", "GET", status, h, body)
				if (h.Get("WWW-Authenticate") != "") != tc.challenge {
					t.Fatal("Basic challenge emission changed")
				}
			})
		}
	})
	t.Run("public_key_metadata_and_mutations", func(t *testing.T) {
		token := f.login(t, "keymember")
		profile := func(input map[string]any, status int) map[string]any {
			t.Helper()
			request, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			h, body := f.request(t, "POST", "/api/profile", token, string(request), status)
			validate(t, "/api/profile", "POST", status, h, body)
			var fields map[string]any
			if json.Unmarshal(body, &fields) != nil {
				t.Fatal("invalid profile JSON")
			}
			return fields
		}
		add := func(usage, content string) map[string]any {
			return map[string]any{"kind": "add_user_" + usage + "_key", "title": "Upload title", "description": "", "content": content}
		}
		list := func(usage string) []any {
			t.Helper()
			fields := profile(map[string]any{"kind": "fetch_user_" + usage + "_keys"}, 200)
			entries, ok := fields["entries"].([]any)
			if !ok {
				t.Fatal("profile did not return an inventory")
			}
			for _, entry := range entries {
				component(t, "ProfilePublicKeyRecord", entry)
			}
			return entries
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
		for _, tc := range []struct {
			content string
			status  int
		}{{sshText, 200}, {" \n" + sshText, 400}, {pemText, 200}, {" \n" + pemText, 400}, {profileUnsupportedSSHKey(t), 400}} {
			fields := profile(map[string]any{"kind": "test_user_ssh_key", "content": tc.content}, tc.status)
			if tc.status == 200 {
				component(t, "ProfileDiagnostic", fields["entry"])
			}
		}
		profile(add("ssh", " \n"+sshText+"\n"), 200)
		profile(add("ssh", pemText), 400)
		keys := list("ssh")
		if len(keys) != 1 {
			t.Fatal("cross-format duplicate altered inventory")
		}
		stored := keys[0].(map[string]any)
		if stored["comment"] != "inline@example.test" || stored["fingerprint"] != ssh.FingerprintSHA256(public) {
			t.Fatal("SSH parser metadata changed")
		}
		profile(map[string]any{"kind": "test_user_ssh_key", "content": stored["payload"]}, 400)
		profile(map[string]any{"kind": "test_user_ssh_key", "content": "ssh-rsa " + strings.TrimSpace(stored["openssh"].(string))}, 200)
		pgp, err := os.ReadFile("../../testdata/gpg/linux_gpg_pub.pem")
		if err != nil {
			t.Fatal(err)
		}
		for _, content := range []string{string(pgp), string(pgp) + "\n" + string(pgp)} {
			fields := profile(map[string]any{"kind": "test_user_gpg_key", "content": content}, 200)
			component(t, "ProfileDiagnostic", fields["entry"])
			if fields["entry"].(map[string]any)["fingerprint"] != "4cca1eaf950cee4ab83976dca040830f7fac5991" {
				t.Fatal("OpenPGP did not use the first armored block")
			}
		}
		profile(add("gpg", string(pgp)), 200)
		pgpKeys := list("gpg")
		if len(pgpKeys) != 1 || pgpKeys[0].(map[string]any)["id"] != "a040830f7fac5991" {
			t.Fatal("OpenPGP record ID is not the primary-key ID")
		}
		for _, cfg := range []*packet.Config{{RSABits: 2048}, {RSABits: 2048, V6Keys: true}, {Algorithm: packet.PubKeyAlgoEdDSA}} {
			entity, err := openpgp.NewEntity("Fixture", "", "fixture@example.test", cfg)
			if err != nil {
				t.Fatal("cannot generate synthetic OpenPGP key")
			}
			var encoded bytes.Buffer
			writer, err := armor.Encode(&encoded, openpgp.PublicKeyType, nil)
			if err != nil || entity.Serialize(writer) != nil || writer.Close() != nil {
				t.Fatal("cannot encode synthetic public key")
			}
			if cfg.Algorithm == packet.PubKeyAlgoEdDSA {
				fields := profile(map[string]any{"kind": "test_user_gpg_key", "content": encoded.String()}, 400)
				if message, _ := fields["message"].(string); !strings.Contains(message, "unsupported public key algo") {
					t.Fatal("OpenPGP rejection was not the algorithm boundary")
				}
				continue
			}
			fields := profile(map[string]any{"kind": "test_user_gpg_key", "content": encoded.String()}, 200)
			component(t, "ProfileDiagnostic", fields["entry"])
			status := 200
			if cfg.V6Keys {
				status = 400 // distinct RSA key, same empty-MD5 duplicate comparison
			}
			profile(add("gpg", encoded.String()), status)
		}
		if len(list("gpg")) != 2 {
			t.Fatal("same-algorithm PGP duplicate behavior changed")
		}
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
		ecdhPrimary := *entity.Subkeys[0].PublicKey
		ecdhPrimary.IsSubkey = false
		fields := profile(map[string]any{"kind": "test_user_gpg_key", "content": armorPackets(ecdhPrimary.Serialize)}, 400)
		if message, _ := fields["message"].(string); !strings.Contains(message, "primary key cannot be used for signatures") {
			t.Fatal("ECDH primary did not fail at the entity reader")
		}
		multiple := armorPackets(func(w io.Writer) error {
			if err := entity.Serialize(w); err != nil {
				return err
			}
			return entity.Serialize(w)
		})
		profile(map[string]any{"kind": "test_user_gpg_key", "content": multiple}, 400)
		tampered := *entity
		tampered.Identities = make(map[string]*openpgp.Identity)
		for name, id := range entity.Identities {
			copy := *id
			copy.UserId = packet.NewUserId("Changed", "", "changed@example.test")
			tampered.Identities[name] = &copy
		}
		fields = profile(map[string]any{"kind": "test_user_gpg_key", "content": armorPackets(tampered.Serialize)}, 400)
		if message, _ := fields["message"].(string); !strings.Contains(message, "self-signature invalid") {
			t.Fatal("modified identity did not fail self-signature validation")
		}
		// Verify with synthetic, disposable material that the public armor label
		// does not cause the selected parser to discard secret-key packets.
		secretArmor := armorPackets(func(w io.Writer) error { return entity.SerializePrivateWithoutSigning(w, nil) })
		profile(map[string]any{"kind": "test_user_gpg_key", "content": secretArmor}, 200)
		profile(add("gpg", secretArmor), 200)
		foundSecret := false
		for _, record := range list("gpg") {
			stored := record.(map[string]any)
			if stored["type"] != "ecdsa" {
				continue
			}
			parsed, err := openpgp.ReadArmoredKeyRing(strings.NewReader(stored["payload"].(string)))
			if err != nil || len(parsed) != 1 || parsed[0].PrivateKey == nil {
				t.Fatal("stored packet-kind contract changed")
			}
			profile(map[string]any{"kind": "delete_user_gpg_key", "id": stored["id"]}, 200)
			foundSecret = true
		}
		if !foundSecret {
			t.Fatal("synthetic ECDSA record was not returned")
		}
		// Fetch is category-specific; delete delegates to owned ID only.
		pgpID, sshID := pgpKeys[0].(map[string]any)["id"], stored["id"]
		profile(map[string]any{"kind": "fetch_user_ssh_key", "id": pgpID}, 500)
		profile(map[string]any{"kind": "fetch_user_gpg_key", "id": sshID}, 500)
		profile(map[string]any{"kind": "fetch_user_ssh_key", "id": " " + sshID.(string)}, 500)
		profile(map[string]any{"kind": "delete_user_ssh_key", "id": pgpID}, 200)
		profile(map[string]any{"kind": "fetch_user_gpg_key", "id": pgpID}, 500)
		profile(map[string]any{"kind": "delete_user_gpg_key", "id": sshID}, 200)
		if len(list("ssh")) != 0 || len(list("gpg")) != 1 {
			t.Fatal("cross-category deletion changed unrelated records")
		}
	})
}

func profileUnsupportedSSHKey(t *testing.T) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(public))
}
