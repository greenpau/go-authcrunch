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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// MfaTokenBundle is a collection of public keys.
type MfaTokenBundle struct {
	tokens []*MfaToken
	size   int
}

// MfaToken is a puiblic key in a public-private key pair.
type MfaToken struct {
	ID               string            `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Type             string            `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Algorithm        string            `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Comment          string            `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Secret           string            `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Period           int               `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits           int               `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Expired          bool              `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt        time.Time         `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt        time.Time         `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled         bool              `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt       time.Time         `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
	Device           *MfaDevice        `json:"device,omitempty" xml:"device,omitempty" yaml:"device,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty" xml:"parameters,omitempty" yaml:"parameters,omitempty"`
	Flags            map[string]bool   `json:"flags,omitempty" xml:"flags,omitempty" yaml:"flags,omitempty"`
	SignatureCounter uint32            `json:"signature_counter,omitempty" xml:"signature_counter,omitempty" yaml:"signature_counter,omitempty"`
	pubkeyECDSA      *ecdsa.PublicKey
	pubkeyRSA        *rsa.PublicKey
}

// MfaDevice is the hardware device associated with MfaToken.
type MfaDevice struct {
	Name   string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Vendor string `json:"vendor,omitempty" xml:"vendor,omitempty" yaml:"vendor,omitempty"`
	Type   string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// NewMfaTokenBundle returns an instance of MfaTokenBundle.
func NewMfaTokenBundle() *MfaTokenBundle {
	return &MfaTokenBundle{
		tokens: []*MfaToken{},
	}
}

// Add adds MfaToken to MfaTokenBundle.
func (b *MfaTokenBundle) Add(k *MfaToken) {
	b.tokens = append(b.tokens, k)
	b.size++
}

// Get returns MfaToken instances of the MfaTokenBundle.
func (b *MfaTokenBundle) Get() []*MfaToken {
	return b.tokens
}

// Size returns the number of MfaToken instances in MfaTokenBundle.
func (b *MfaTokenBundle) Size() int {
	return b.size
}

// NewMfaToken returns an instance of MfaToken.
func NewMfaToken(req *requests.Request) (*MfaToken, error) {
	p := &MfaToken{
		ID:         GetRandomString(40),
		CreatedAt:  time.Now().UTC(),
		Parameters: make(map[string]string),
		Flags:      make(map[string]bool),
		Comment:    req.MfaToken.Comment,
		Type:       req.MfaToken.Type,
	}

	if req.MfaToken.Disabled {
		p.Disabled = true
		p.DisabledAt = time.Now().UTC()
	}

	switch p.Type {
	case "totp":
		// Shared Secret
		p.Secret = req.MfaToken.Secret
		// Algorithm
		p.Algorithm = strings.ToLower(req.MfaToken.Algorithm)
		switch p.Algorithm {
		case "sha1", "sha256", "sha512":
		case "":
			p.Algorithm = "sha1"
		default:
			return nil, errors.ErrMfaTokenInvalidAlgorithm.WithArgs(p.Algorithm)
		}
		req.MfaToken.Algorithm = p.Algorithm

		// Period
		p.Period = req.MfaToken.Period
		if p.Period < 30 || p.Period > 300 {
			return nil, errors.ErrMfaTokenInvalidPeriod.WithArgs(p.Period)
		}
		// Digits
		p.Digits = req.MfaToken.Digits
		if p.Digits == 0 {
			p.Digits = 6
		}
		if p.Digits < 4 || p.Digits > 8 {
			return nil, errors.ErrMfaTokenInvalidDigits.WithArgs(p.Digits)
		}
		// Codes
		if err := p.ValidateCodeWithTime(req.MfaToken.Passcode, time.Now().Add(-time.Second*time.Duration(p.Period)).UTC()); err != nil {
			return nil, err
		}
	case "u2f":
		r := &WebAuthnRegisterRequest{}
		if req.WebAuthn.Register == "" {
			return nil, errors.ErrWebAuthnRegisterNotFound
		}
		if req.WebAuthn.Challenge == "" {
			return nil, errors.ErrWebAuthnChallengeNotFound
		}

		// Decode WebAuthn Register.
		decoded, err := base64.StdEncoding.DecodeString(req.WebAuthn.Register)
		if err != nil {
			return nil, errors.ErrWebAuthnParse.WithArgs(err)
		}
		if err := json.Unmarshal([]byte(decoded), r); err != nil {
			return nil, errors.ErrWebAuthnParse.WithArgs(err)
		}
		// Set WebAuthn Challenge as Secret.
		p.Secret = req.WebAuthn.Challenge

		if r.ID == "" {
			return nil, errors.ErrWebAuthnEmptyRegisterID
		}

		switch r.Type {
		case "public-key":
		case "":
			return nil, errors.ErrWebAuthnEmptyRegisterKeyType
		default:
			return nil, errors.ErrWebAuthnInvalidRegisterKeyType.WithArgs(r.Type)
		}

		for _, tr := range r.Transports {
			switch tr {
			case "usb":
			case "nfc":
			case "ble":
			case "internal":
			case "":
				return nil, errors.ErrWebAuthnEmptyRegisterTransport
			default:
				return nil, errors.ErrWebAuthnInvalidRegisterTransport.WithArgs(tr)
			}
		}

		if r.AttestationObject == nil {
			return nil, errors.ErrWebAuthnRegisterAttestationObjectNotFound
		}
		if r.AttestationObject.AuthData == nil {
			return nil, errors.ErrWebAuthnRegisterAuthDataNotFound
		}

		// Extract rpIdHash from authData.
		if r.AttestationObject.AuthData.RelyingPartyID == "" {
			return nil, errors.ErrWebAuthnRegisterEmptyRelyingPartyID
		}
		p.Parameters["rp_id_hash"] = r.AttestationObject.AuthData.RelyingPartyID

		// Extract flags from authData.
		if r.AttestationObject.AuthData.Flags == nil {
			return nil, errors.ErrWebAuthnRegisterEmptyFlags
		}
		for k, v := range r.AttestationObject.AuthData.Flags {
			p.Flags[k] = v
		}

		// Extract signature counter from authData.
		p.SignatureCounter = r.AttestationObject.AuthData.SignatureCounter

		// Extract public key from credentialData.
		if r.AttestationObject.AuthData.CredentialData == nil {
			return nil, errors.ErrWebAuthnRegisterCredentialDataNotFound
		}

		if r.AttestationObject.AuthData.CredentialData.PublicKey == nil {
			return nil, errors.ErrWebAuthnRegisterPublicKeyNotFound
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#key-type
		var keyType string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["key_type"]; exists {
			switch v.(float64) {
			case 2:
				keyType = "ec2"
			case 3:
				keyType = "rsa"
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyUnsupported.WithArgs(v)
			}
		} else {
			return nil, errors.ErrWebAuthnRegisterPublicKeyTypeNotFound
		}

		// See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
		var keyAlgo string
		if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["algorithm"]; exists {
			switch v.(float64) {
			case -7:
				keyAlgo = "es256"
			case -257:
				keyAlgo = "rs256"
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyAlgorithmUnsupported.WithArgs(v)
			}
		} else {
			return nil, errors.ErrWebAuthnRegisterPublicKeyAlgorithmNotFound
		}

		switch keyType {
		case "ec2":
			switch keyAlgo {
			case "es256":
				// See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
				var curveType, curveXcoord, curveYcoord string
				if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_type"]; exists {
					switch v.(float64) {
					case 1:
						curveType = "p256"
					default:
						return nil, errors.ErrWebAuthnRegisterPublicKeyCurveUnsupported.WithArgs(v)
					}
				}
				if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_x"]; exists {
					curveXcoord = v.(string)
				}
				if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["curve_y"]; exists {
					curveYcoord = v.(string)
				}
				p.Parameters["curve_type"] = curveType
				p.Parameters["curve_xcoord"] = curveXcoord
				p.Parameters["curve_ycoord"] = curveYcoord
			default:
				return nil, errors.ErrWebAuthnRegisterPublicKeyTypeAlgorithmUnsupported.WithArgs(keyType, keyAlgo)
			}
		default:
			if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["exponent"]; exists {
				p.Parameters["exponent"] = v.(string)
			} else {
				return nil, errors.ErrWebAuthnRegisterPublicKeyParamNotFound.WithArgs(keyType, keyAlgo, "exponent")
			}
			if v, exists := r.AttestationObject.AuthData.CredentialData.PublicKey["modulus"]; exists {
				p.Parameters["modulus"] = v.(string)
			} else {
				return nil, errors.ErrWebAuthnRegisterPublicKeyParamNotFound.WithArgs(keyType, keyAlgo, "modulus")
			}
		}

		p.Parameters["u2f_id"] = r.ID
		p.Parameters["u2f_type"] = r.Type
		p.Parameters["u2f_transports"] = strings.Join(r.Transports, ",")
		p.Parameters["key_type"] = keyType
		p.Parameters["key_algo"] = keyAlgo
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AttestationStatement.Certificates)
		//return nil, fmt.Errorf("XXX: %v", r.AttestationObject.AuthData.CredentialData)

		if p.Comment == "" {
			p.Comment = fmt.Sprintf("T%d", time.Now().UTC().Unix())
		}
	case "":
		return nil, errors.ErrMfaTokenTypeEmpty
	default:
		return nil, errors.ErrMfaTokenInvalidType.WithArgs(p.Type)
	}

	return p, nil
}

// WebAuthnRequest processes WebAuthn requests.
func (p *MfaToken) WebAuthnRequest(payload string) (*WebAuthnAuthenticateRequest, error) {
	switch p.Type {
	case "u2f":
	default:
		return nil, errors.ErrWebAuthnRequest.WithArgs("unsupported token type")
	}

	for _, reqParam := range []string{"u2f_id", "key_type"} {
		if _, exists := p.Parameters[reqParam]; !exists {
			return nil, errors.ErrWebAuthnRequest.WithArgs(reqParam + " not found")
		}
	}

	switch p.Parameters["key_type"] {
	case "ec2":
		if p.pubkeyECDSA == nil {
			if err := p.derivePublicKey(p.Parameters); err != nil {
				return nil, err
			}
		}
	case "rsa":
		if p.pubkeyRSA == nil {
			if err := p.derivePublicKey(p.Parameters); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.ErrWebAuthnRequest.WithArgs("unsupported key type")
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}

	r := &WebAuthnAuthenticateRequest{}
	if err := json.Unmarshal([]byte(decoded), r); err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs(err)
	}

	// Validate key id.
	if p.Parameters["u2f_id"] != r.ID {
		return r, errors.ErrWebAuthnRequest.WithArgs("key id mismatch")
	}

	// Decode ClientDataJSON.
	if strings.TrimSpace(r.ClientDataEncoded) == "" {
		return r, errors.ErrWebAuthnRequest.WithArgs("encoded client data is empty")
	}
	clientDataBytes, err := base64.StdEncoding.DecodeString(r.ClientDataEncoded)
	if err != nil {
		return r, errors.ErrWebAuthnRequest.WithArgs("failed to decode client data")
	}
	clientData := &ClientData{}
	if err := json.Unmarshal(clientDataBytes, clientData); err != nil {
		return nil, errors.ErrWebAuthnParse.WithArgs("failed to unmarshal client data")
	}
	r.ClientData = clientData
	r.clientDataBytes = clientDataBytes
	clientDataHash := sha256.Sum256(clientDataBytes)
	r.ClientDataEncoded = ""
	if r.ClientData == nil {
		return r, errors.ErrWebAuthnRequest.WithArgs("client data is nil")
	}

	// Decode Signature.
	if strings.TrimSpace(r.SignatureEncoded) == "" {
		return r, errors.ErrWebAuthnRequest.WithArgs("encoded signature is empty")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(r.SignatureEncoded)
	if err != nil {
		return r, errors.ErrWebAuthnRequest.WithArgs("failed to decode signature")
	}
	r.signatureBytes = signatureBytes
	r.SignatureEncoded = ""

	// Decode Authenticator Data.
	// See also https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
	if strings.TrimSpace(r.AuthDataEncoded) == "" {
		return r, errors.ErrWebAuthnRequest.WithArgs("encoded authenticator data is empty")
	}
	authDataBytes, err := base64.StdEncoding.DecodeString(r.AuthDataEncoded)
	if err != nil {
		return r, errors.ErrWebAuthnRequest.WithArgs("failed to decode auth data")
	}
	if err := r.unpackAuthData(authDataBytes); err != nil {
		return r, errors.ErrWebAuthnRequest.WithArgs(err)
	}
	r.authDataBytes = authDataBytes
	if r.AuthData == nil {
		return r, errors.ErrWebAuthnRequest.WithArgs("auth data is nil")
	}

	// Verifying an Authentication Assertion
	// See also https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion

	// Verify that the value of C.type is the string webauthn.get.
	if r.ClientData.Type != "webauthn.get" {
		return r, errors.ErrWebAuthnRequest.WithArgs("client data type is not webauthn.get")
	}

	// Verify that the value of C.crossOrigin is false.
	if r.ClientData.CrossOrigin == true {
		return r, errors.ErrWebAuthnRequest.WithArgs("client data cross origin true is not supported")
	}

	// TODO(greenpau): Verify that the value of C.origin matches the Relying Party's origin.

	// Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by
	// the Relying Party.
	if r.AuthData.RelyingPartyID != p.Parameters["rp_id_hash"] {
		return r, errors.ErrWebAuthnRequest.WithArgs("rpIdHash mismatch")
	}

	// Verify that the User Present bit of the flags in authData is set.
	if r.AuthData.Flags["UP"] != true {
		return r, errors.ErrWebAuthnRequest.WithArgs("authData User Present bit is not set")
	}

	// TODO(greenpau): If user verification is required for this assertion, verify that the User
	// Verified bit of the flags in authData is set.
	// This requires checking UV key in p.Flags.

	// Verify signature.
	signedData := append(authDataBytes, clientDataHash[:]...)
	crt := &x509.Certificate{}
	switch p.Parameters["key_type"] {
	case "ec2":
		crt.PublicKey = p.pubkeyECDSA
	case "rsa":
		crt.PublicKey = p.pubkeyRSA
	}

	switch p.Parameters["key_algo"] {
	case "es256":
		if err := crt.CheckSignature(x509.ECDSAWithSHA256, signedData, signatureBytes); err != nil {
			return r, errors.ErrWebAuthnRequest.WithArgs(err)
		}
	case "rs256":
		if err := crt.CheckSignature(x509.SHA256WithRSA, signedData, signatureBytes); err != nil {
			return r, errors.ErrWebAuthnRequest.WithArgs(err)
		}
	default:
		return r, errors.ErrWebAuthnRequest.WithArgs("failed signature verification due to unsupported algo")
	}

	return r, nil
}

// Disable disables MfaToken instance.
func (p *MfaToken) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

// ValidateCode validates a passcode
func (p *MfaToken) ValidateCode(code string) error {
	switch p.Type {
	case "totp":
	default:
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("unsupported token type")
	}
	ts := time.Now().UTC()
	return p.ValidateCodeWithTime(code, ts)
}

// ValidateCodeWithTime validates a passcode at a particular time.
func (p *MfaToken) ValidateCodeWithTime(code string, ts time.Time) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("empty")
	}
	if len(code) < 4 || len(code) > 8 {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("not 4-8 characters long")
	}
	if len(code) != p.Digits {
		return errors.ErrMfaTokenInvalidPasscode.WithArgs("digits length mismatch")
	}
	tp := uint64(math.Floor(float64(ts.Unix()) / float64(p.Period)))
	tps := []uint64{}
	tps = append(tps, tp)
	tps = append(tps, tp+uint64(1))
	tps = append(tps, tp-uint64(1))
	for _, uts := range tps {
		localCode, err := generateMfaCode(p.Secret, p.Algorithm, p.Digits, uts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(localCode), []byte(code)) == 1 {
			return nil
		}
	}
	return errors.ErrMfaTokenInvalidPasscode.WithArgs("failed")
}

func generateMfaCode(secret, algo string, digits int, ts uint64) (string, error) {
	var mac hash.Hash
	secretBytes := []byte(secret)
	switch algo {
	case "sha1":
		mac = hmac.New(sha1.New, secretBytes)
	case "sha256":
		mac = hmac.New(sha256.New, secretBytes)
	case "sha512":
		mac = hmac.New(sha512.New, secretBytes)
	case "":
		return "", errors.ErrMfaTokenEmptyAlgorithm
	default:
		return "", errors.ErrMfaTokenInvalidAlgorithm.WithArgs(algo)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, ts)
	mac.Write(buf)
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0xf
	val := int64(((int(sum[off]) & 0x7f) << 24) |
		((int(sum[off+1] & 0xff)) << 16) |
		((int(sum[off+2] & 0xff)) << 8) |
		(int(sum[off+3]) & 0xff))
	mod := int32(val % int64(math.Pow10(digits)))
	wrap := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(wrap, mod), nil
}

func (p *MfaToken) derivePublicKey(params map[string]string) error {
	for _, reqParam := range []string{"key_algo"} {
		if _, exists := params[reqParam]; !exists {
			return errors.ErrWebAuthnRequest.WithArgs(reqParam + " not found")
		}
	}
	switch params["key_algo"] {
	case "es256":
		for _, reqParam := range []string{"curve_xcoord", "curve_ycoord"} {
			if _, exists := params[reqParam]; !exists {
				return errors.ErrWebAuthnRequest.WithArgs(reqParam + " not found")
			}
		}
		var coords []*big.Int
		for _, ltr := range []string{"x", "y"} {
			coord := "curve_" + ltr + "coord"
			b, err := base64.StdEncoding.DecodeString(params[coord])
			if err != nil {
				return errors.ErrWebAuthnRegisterPublicKeyCurveCoord.WithArgs(ltr, err)
			}
			if len(b) != 32 {
				return errors.ErrWebAuthnRegisterPublicKeyCurveCoord.WithArgs(ltr, "not 32 bytes in length")
			}
			i := new(big.Int)
			i.SetBytes(b)
			coords = append(coords, i)
		}
		p.pubkeyECDSA = &ecdsa.PublicKey{Curve: elliptic.P256(), X: coords[0], Y: coords[1]}
	case "rs256":
		for _, reqParam := range []string{"exponent", "modulus"} {
			if _, exists := params[reqParam]; !exists {
				return errors.ErrWebAuthnRequest.WithArgs(reqParam + " not found")
			}
		}
		nb, err := base64.StdEncoding.DecodeString(params["modulus"])
		if err != nil {
			return errors.ErrWebAuthnRegisterPublicKeyMaterial.WithArgs("modulus", err)
		}
		n := new(big.Int)
		n.SetBytes(nb)

		/*
			ne, err := base64.StdEncoding.DecodeString(params["exponent"])
			if err != nil {
				return errors.ErrWebAuthnRegisterPublicKeyMaterial.WithArgs("exponent", err)
			}
		*/
		p.pubkeyRSA = &rsa.PublicKey{
			N: n,
			E: 65537,
		}
		// return errors.ErrWebAuthnRegisterPublicKeyAlgorithmUnsupported.WithArgs(params["key_algo"])
	}
	return nil
}

func (r *WebAuthnAuthenticateRequest) unpackAuthData(b []byte) error {
	data := new(AuthData)
	if len(b) < 37 {
		return fmt.Errorf("auth data is less than 37 bytes long")
	}
	data.RelyingPartyID = fmt.Sprintf("%x", b[0:32])
	data.Flags = make(map[string]bool)
	for _, st := range []struct {
		k string
		v byte
	}{
		{"UP", 0x001},
		{"RFU1", 0x002},
		{"UV", 0x004},
		{"RFU2a", 0x008},
		{"RFU2b", 0x010},
		{"RFU2c", 0x020},
		{"AT", 0x040},
		{"ED", 0x080},
	} {
		if (b[32] & st.v) == st.v {
			data.Flags[st.k] = true
		} else {
			data.Flags[st.k] = false
		}
	}
	data.SignatureCounter = binary.BigEndian.Uint32(b[33:37])

	// TODO(greenpau): implement AT parser.
	// if (data.Flags["AT"] == true) && len(b) > 37 {
	//   // Extract attested credentials data.
	// }

	r.AuthData = data
	return nil
}
