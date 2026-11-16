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

package authn_test

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Sign the altered response with the fixture's trusted IdP key. Independently
// verify the signature so rejection cannot be attributed to a broken signature.
func signedSAMLE2EAssertion(t *testing.T, f *samlE2EFixture, encoded string, alter func(*etree.Element)) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatal(err)
	}
	response := doc.Root()
	assertion := response.SelectElement("Assertion")
	if assertion == nil || assertion.SelectElement("Issuer") == nil || assertion.SelectElement("Subject") == nil {
		t.Fatal("fixture did not produce a complete assertion")
	}
	for _, element := range []*etree.Element{response, assertion} {
		if signature := element.SelectElement("Signature"); signature != nil {
			element.RemoveChild(signature)
		}
	}
	alter(assertion)
	signer, err := dsig.NewSigningContext(f.signingKey, [][]byte{f.signingCert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	signer.IdAttribute = "ID"
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignEnveloped(response)
	if err != nil {
		t.Fatal(err)
	}
	doc.SetRoot(signed)
	data, err = doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Check the serialized wire document, with the same namespace context and
	// parent/child bookkeeping that the receiving parser will reconstruct.
	wire := etree.NewDocument()
	if err := wire.ReadFromBytes(data); err != nil {
		t.Fatal(err)
	}
	verifier := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{f.signingCert}})
	verifier.IdAttribute = "ID"
	if _, err := verifier.Validate(wire.Root()); err != nil {
		t.Fatalf("fixture signature verification failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func TestE2ESAMLAssertionIdentityValidation(t *testing.T) {
	for _, name := range []string{"valid", "missing_issuer", "foreign_nameid", "unqualified_nameid"} {
		t.Run(name, func(t *testing.T) {
			f := newSAMLE2EFixture(t)
			form := f.begin(t)
			form.Set("SAMLResponse", signedSAMLE2EAssertion(t, f, form.Get("SAMLResponse"), func(assertion *etree.Element) {
				switch name {
				case "missing_issuer":
					assertion.RemoveChild(assertion.SelectElement("Issuer"))
				case "foreign_nameid", "unqualified_nameid":
					identifier := assertion.SelectElement("Subject").SelectElement("NameID")
					if identifier == nil {
						t.Fatal("fixture did not produce a subject identifier")
					}
					identifier.Space = ""
					namespace := ""
					if name == "foreign_nameid" {
						namespace = "urn:authcrunch:test:foreign"
					}
					identifier.CreateAttr("xmlns", namespace)
				}
			}))
			resp := samlE2EPost(t, f.client, f.portalURL+"/auth/saml/upstream", form)
			if name == "valid" {
				if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Authorization") == "" {
					t.Fatalf("valid signed assertion did not issue credentials: HTTP %d", resp.StatusCode)
				}
				return
			}
			if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Authorization") != "" {
				t.Fatalf("invalid signed assertion was not denied: HTTP %d", resp.StatusCode)
			}
			for _, cookie := range resp.Cookies() {
				if cookie.Name == "saml_e2e_token" && cookie.Value != "" {
					t.Fatal("invalid assertion issued an access cookie")
				}
			}
			// The rejected callback consumes its transaction; the next legitimate
			// signed login must still succeed on the same live portal.
			resp = samlE2EPost(t, f.client, f.portalURL+"/auth/saml/upstream", f.begin(t))
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Authorization") == "" {
				t.Fatalf("fresh login after rejection failed: HTTP %d", resp.StatusCode)
			}
		})
	}
}
