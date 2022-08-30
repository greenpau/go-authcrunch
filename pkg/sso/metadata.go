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
	"bytes"
	"encoding/base64"
	"encoding/xml"
)

// EntityDescriptor TODO.
type EntityDescriptor struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	ID       string   `xml:",attr,omitempty"`
	EntityID string   `xml:"entityID,attr"`
}

// X509Data TODO.
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

// KeyInfo TODO.
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data *X509Data
}

// KeyDescriptor TODO.
type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr,omitempty"`
	KeyInfo KeyInfo
}

// Service TODO.
type Service struct {
	Binding  string `xml:",attr"`
	Location string `xml:",attr"`
}

// SingleSignOnService TODO.
type SingleSignOnService struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Service
}

// IDPSSODescriptor TODO.
type IDPSSODescriptor struct {
	XMLName                    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	WantAuthnRequestsSigned    bool     `xml:",attr"`
	ProtocolSupportEnumeration string   `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              KeyDescriptor
	NameIDFormat               string `xml:"NameIDFormat"`
	SingleSignOnService        []SingleSignOnService
}

// IDPEntityDescriptor TODO.
type IDPEntityDescriptor struct {
	*EntityDescriptor
	IDPSSODescriptor *IDPSSODescriptor
}

// GetMetadata returns the contents of metadata.xml.
func (p *Provider) GetMetadata() ([]byte, error) {
	if len(p.metadata) > 0 {
		return p.metadata, nil
	}
	entity := &IDPEntityDescriptor{
		EntityDescriptor: &EntityDescriptor{
			EntityID: p.config.EntityID,
		},
		IDPSSODescriptor: &IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: KeyDescriptor{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: &X509Data{
						X509Certificate: base64.StdEncoding.EncodeToString(p.cert.Raw),
					},
				},
			},
			WantAuthnRequestsSigned: false,
			NameIDFormat:            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
	}

	for _, location := range p.config.Locations {
		svc := SingleSignOnService{
			Service: Service{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: location,
			},
		}
		entity.IDPSSODescriptor.SingleSignOnService = append(entity.IDPSSODescriptor.SingleSignOnService, svc)
	}

	var b bytes.Buffer
	b.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(&b)
	encoder.Indent("", "  ")
	if err := encoder.Encode(entity); err != nil {
		return nil, err
	}
	output := bytes.ReplaceAll(b.Bytes(), []byte("></SingleSignOnService>"), []byte("/>"))
	output = bytes.ReplaceAll(output,
		[]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`),
		[]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"`))
	output = bytes.ReplaceAll(output,
		[]byte(`<IDPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`),
		[]byte(`<md:IDPSSODescriptor`))
	output = bytes.ReplaceAll(output,
		[]byte(`<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`),
		[]byte(`<md:KeyDescriptor`))
	output = bytes.ReplaceAll(output,
		[]byte(`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`),
		[]byte(`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`))
	output = bytes.ReplaceAll(output,
		[]byte(`<X509Data xmlns="http://www.w3.org/2000/09/xmldsig#">`),
		[]byte(`<ds:X509Data>`))
	output = bytes.ReplaceAll(output,
		[]byte(`<X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">`),
		[]byte(`<ds:X509Certificate>`))
	output = bytes.ReplaceAll(output,
		[]byte(`SingleSignOnService xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`),
		[]byte(`md:SingleSignOnService`))
	output = bytes.ReplaceAll(output, []byte(`</IDPSSODescriptor>`), []byte(`</md:IDPSSODescriptor>`))
	output = bytes.ReplaceAll(output, []byte(`</EntityDescriptor>`), []byte(`</md:EntityDescriptor>`))
	output = bytes.ReplaceAll(output, []byte(`</X509Data>`), []byte(`</ds:X509Data>`))
	output = bytes.ReplaceAll(output, []byte(`</KeyInfo>`), []byte(`</ds:KeyInfo>`))
	output = bytes.ReplaceAll(output, []byte(`</KeyDescriptor>`), []byte(`</md:KeyDescriptor>`))
	output = bytes.ReplaceAll(output, []byte(`</X509Certificate>`), []byte(`</ds:X509Certificate>`))
	output = bytes.ReplaceAll(output, []byte(`NameIDFormat>`), []byte(`md:NameIDFormat>`))
	p.metadata = output
	return p.metadata, nil
}
