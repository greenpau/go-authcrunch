module github.com/greenpau/go-authcrunch

go 1.18

require (
	github.com/crewjam/saml v0.4.10
	github.com/emersion/go-sasl v0.0.0-20220912192320-0145f2c60ead
	github.com/emersion/go-smtp v0.15.0
	github.com/go-ldap/ldap/v3 v3.4.4
	github.com/golang-jwt/jwt/v4 v4.4.3
	github.com/google/go-cmp v0.5.9
	github.com/google/uuid v1.3.0
	github.com/greenpau/versioned v1.0.27
	github.com/iancoleman/strcase v0.2.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/urfave/cli/v2 v2.23.7
	go.uber.org/zap v1.24.0
	golang.org/x/crypto v0.4.0
	golang.org/x/net v0.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/beevik/etree v1.1.0 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/crewjam/httperr v0.2.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/jonboulle/clockwork v0.3.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/goxmldsig v1.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/testify v1.8.1 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/goleak v1.2.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
)

replace github.com/crewjam/saml v0.4.10 => github.com/greenpau/origin_crewjam_saml v0.4.11-0.20221229165346-936eba92623a
