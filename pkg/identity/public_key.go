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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh"
	"strconv"
	"strings"
	"time"
)

var supportedPublicKeyTypes = map[string]bool{
	"ssh": true,
	"gpg": true,
}

// PublicKeyBundle is a collection of public keys.
type PublicKeyBundle struct {
	keys []*PublicKey
	size int
}

// PublicKey is a puiblic key in a public-private key pair.
type PublicKey struct {
	ID    string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Usage string `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	// Type is any of the following: dsa, rsa, ecdsa, ed25519
	Type           string    `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Fingerprint    string    `json:"fingerprint,omitempty" xml:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	FingerprintMD5 string    `json:"fingerprint_md5,omitempty" xml:"fingerprint_md5,omitempty" yaml:"fingerprint_md5,omitempty"`
	Comment        string    `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Payload        string    `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	OpenSSH        string    `json:"openssh,omitempty" xml:"openssh,omitempty" yaml:"openssh,omitempty"`
	Expired        bool      `json:"expired,omitempty" xml:"expired,omitempty" yaml:"expired,omitempty"`
	ExpiredAt      time.Time `json:"expired_at,omitempty" xml:"expired_at,omitempty" yaml:"expired_at,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	Disabled       bool      `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	DisabledAt     time.Time `json:"disabled_at,omitempty" xml:"disabled_at,omitempty" yaml:"disabled_at,omitempty"`
}

// NewPublicKeyBundle returns an instance of PublicKeyBundle.
func NewPublicKeyBundle() *PublicKeyBundle {
	return &PublicKeyBundle{
		keys: []*PublicKey{},
	}
}

// Add adds PublicKey to PublicKeyBundle.
func (b *PublicKeyBundle) Add(k *PublicKey) {
	b.keys = append(b.keys, k)
	b.size++
}

// Get returns PublicKey instances of the PublicKeyBundle.
func (b *PublicKeyBundle) Get() []*PublicKey {
	return b.keys
}

// Size returns the number of PublicKey instances in PublicKeyBundle.
func (b *PublicKeyBundle) Size() int {
	return b.size
}

// NewPublicKey returns an instance of PublicKey.
func NewPublicKey(r *requests.Request) (*PublicKey, error) {
	p := &PublicKey{
		Comment:   r.Key.Comment,
		ID:        GetRandomString(40),
		Payload:   r.Key.Payload,
		Usage:     r.Key.Usage,
		CreatedAt: time.Now().UTC(),
	}
	if err := p.parse(); err != nil {
		return nil, err
	}
	if r.Key.Disabled {
		p.Disabled = true
		p.DisabledAt = time.Now().UTC()
	}
	return p, nil
}

// Disable disables PublicKey instance.
func (p *PublicKey) Disable() {
	p.Expired = true
	p.ExpiredAt = time.Now().UTC()
	p.Disabled = true
	p.DisabledAt = time.Now().UTC()
}

func (p *PublicKey) parse() error {
	if _, exists := supportedPublicKeyTypes[p.Usage]; !exists {
		return errors.ErrPublicKeyInvalidUsage.WithArgs(p.Usage)
	}
	if p.Payload == "" {
		return errors.ErrPublicKeyEmptyPayload
	}
	switch {
	case strings.Contains(p.Payload, "RSA PUBLIC KEY"):
		return p.parsePublicKeyRSA()
	case strings.HasPrefix(p.Payload, "ssh-rsa "):
		return p.parsePublicKeyOpenSSH()
	case strings.Contains(p.Payload, "BEGIN PGP PUBLIC KEY BLOCK"):
		return p.parsePublicKeyPGP()
	}
	return errors.ErrPublicKeyUsageUnsupported.WithArgs(p.Usage)
}

func (p *PublicKey) parsePublicKeyOpenSSH() error {
	// Attempt parsing as authorized OpenSSH keys.
	payloadBytes := bytes.TrimSpace([]byte(p.Payload))
	i := bytes.IndexAny(payloadBytes, " \t")
	if i == -1 {
		i = len(payloadBytes)
	}

	var comment []byte
	payloadBase64 := payloadBytes[:i]
	if len(payloadBase64) < 20 {
		// skip preamble, i.e. ssh-rsa, etc.
		payloadBase64 = bytes.TrimSpace(payloadBytes[i:])
		i = bytes.IndexAny(payloadBase64, " \t")
		if i > 0 {
			comment = bytes.TrimSpace(payloadBase64[i:])
			payloadBase64 = payloadBase64[:i]
		}
		p.OpenSSH = string(payloadBase64)
	}
	k := make([]byte, base64.StdEncoding.DecodedLen(len(payloadBase64)))
	n, err := base64.StdEncoding.Decode(k, payloadBase64)
	if err != nil {
		return errors.ErrPublicKeyParse.WithArgs(err)
	}
	publicKey, err := ssh.ParsePublicKey(k[:n])
	if err != nil {
		return errors.ErrPublicKeyParse.WithArgs(err)
	}
	p.Type = publicKey.Type()
	if string(comment) != "" {
		p.Comment = string(comment)
	}
	p.FingerprintMD5 = ssh.FingerprintLegacyMD5(publicKey)
	p.Fingerprint = ssh.FingerprintSHA256(publicKey)

	// Convert OpenSSH key to RSA PUBLIC KEY
	switch publicKey.Type() {
	case "ssh-rsa":
		publicKeyBytes := publicKey.Marshal()
		parsedPublicKey, err := ssh.ParsePublicKey(publicKeyBytes)
		if err != nil {
			return errors.ErrPublicKeyParse.WithArgs(err)
		}
		cryptoKey := parsedPublicKey.(ssh.CryptoPublicKey)
		publicCryptoKey := cryptoKey.CryptoPublicKey()
		rsaKey := publicCryptoKey.(*rsa.PublicKey)
		rsaKeyASN1, err := x509.MarshalPKIXPublicKey(rsaKey)
		if err != nil {
			return errors.ErrPublicKeyParse.WithArgs(err)
		}
		encodedKey := pem.EncodeToMemory(&pem.Block{
			Type: "RSA PUBLIC KEY",
			//Bytes: x509.MarshalPKCS1PublicKey(rsaKey),
			Bytes: rsaKeyASN1,
		})
		p.Payload = string(encodedKey)
	default:
		return errors.ErrPublicKeyTypeUnsupported.WithArgs(publicKey.Type())
	}
	return nil
}

func (p *PublicKey) parsePublicKeyPGP() error {
	var user, algo, comment string
	p.Payload = strings.TrimSpace(p.Payload)
	for _, w := range []string{"BEGIN", "END"} {
		s := fmt.Sprintf("-----%s PGP PUBLIC KEY BLOCK-----", w)
		if (w == "BEGIN" && !strings.HasPrefix(p.Payload, s)) || (w == "END" && !strings.HasSuffix(p.Payload, s)) {
			return errors.ErrPublicKeyParse.WithArgs(fmt.Errorf("%s PGP PUBLIC KEY BLOCK not found", w))
		}
	}
	kr, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(p.Payload))
	if err != nil {
		return errors.ErrPublicKeyParse.WithArgs(err)
	}
	if len(kr) != 1 {
		return errors.ErrPublicKeyParse.WithArgs(fmt.Errorf("PGP keyring contains %d entries", len(kr)))
	}
	if kr[0].PrimaryKey == nil {
		return errors.ErrPublicKeyParse.WithArgs(fmt.Errorf("PGP keyring entry has no public key"))
	}
	if kr[0].Identities == nil || len(kr[0].Identities) == 0 {
		return errors.ErrPublicKeyParse.WithArgs(fmt.Errorf("PGP keyring entry has no identities"))
	}
	pk := kr[0].PrimaryKey
	p.ID = strconv.FormatUint(pk.KeyId, 16)
	p.Fingerprint = hex.EncodeToString(pk.Fingerprint[:])
	switch pk.PubKeyAlgo {
	case 1, 2, 3:
		algo = "RSA"
		p.Type = "rsa"
	case 17:
		algo = "DSA"
		p.Type = "dsa"
	case 18:
		algo = "ECDH"
		p.Type = "ecdh"
	case 19:
		algo = "ECDSA"
		p.Type = "ecdsa"
	default:
		return errors.ErrPublicKeyParse.WithArgs(fmt.Errorf("PGP keyring entry has unsupported public key algo %v", pk.PubKeyAlgo))
	}
	for _, u := range kr[0].Identities {
		user = u.Name
		break
	}
	comment = fmt.Sprintf("%s, algo %s, created %s", user, algo, pk.CreationTime.UTC())
	if p.Comment != "" {
		p.Comment = fmt.Sprintf("%s (%s)", p.Comment, comment)
	} else {
		p.Comment = comment
	}
	return nil
}

func (p *PublicKey) parsePublicKeyRSA() error {
	// Processing PEM file format
	if p.Usage != "ssh" {
		return errors.ErrPublicKeyUsagePayloadMismatch.WithArgs(p.Usage)
	}
	block, _ := pem.Decode(bytes.TrimSpace([]byte(p.Payload)))
	if block == nil {
		return errors.ErrPublicKeyBlockType.WithArgs("")
	}
	if block.Type != "RSA PUBLIC KEY" {
		return errors.ErrPublicKeyBlockType.WithArgs(block.Type)
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.ErrPublicKeyParse.WithArgs(err)
	}
	publicKey, err := ssh.NewPublicKey(publicKeyInterface)
	if err != nil {
		return fmt.Errorf("failed ssh.NewPublicKey: %s", err)
	}
	p.Type = publicKey.Type()
	p.FingerprintMD5 = ssh.FingerprintLegacyMD5(publicKey)
	p.Fingerprint = ssh.FingerprintSHA256(publicKey)
	p.Fingerprint = strings.ReplaceAll(p.Fingerprint, "SHA256:", "")
	p.OpenSSH = string(ssh.MarshalAuthorizedKey(publicKey))
	p.OpenSSH = strings.TrimLeft(p.OpenSSH, p.Type+" ")
	return nil
}
