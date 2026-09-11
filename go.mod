module github.com/greenpau/go-authcrunch

go 1.26.0

require (
	github.com/crewjam/saml v0.5.1
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.25.0
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/greenpau/versioned v1.0.36
	github.com/iancoleman/strcase v0.3.0
	github.com/nicksnyder/go-i18n/v2 v2.6.1
	github.com/olekukonko/tablewriter v1.1.4
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/urfave/cli/v2 v2.27.7
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/term v0.46.0
	golang.org/x/text v0.42.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/beevik/etree v1.8.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/greenpau/tested v1.0.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/lint v0.0.0-20241112194109-818c5a804067 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

tool (
	github.com/greenpau/tested
	github.com/greenpau/versioned/cmd/versioned
	golang.org/x/lint/golint
)
