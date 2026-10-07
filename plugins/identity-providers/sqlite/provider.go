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

package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ErrInvalid rejects malformed configuration or trusted issuance input.
var ErrInvalid = errors.New("invalid SQLite ticket input")

// ErrDenied rejects unbound, expired, missing, already-issued or spent tickets.
var ErrDenied = errors.New("SQLite ticket authentication denied")

// ErrFull refuses new browser requests when all live slots are occupied.
var ErrFull = errors.New("SQLite ticket capacity reached")

// ErrUnavailable indicates the current backend cannot be used.
var ErrUnavailable = sqlitedb.ErrUnavailable

// ErrCommitUncertain requires reconciliation; never publish an uncertain ticket or identity.
var ErrCommitUncertain = sqlitedb.ErrCommitUncertain

// Provider owns ticket storage; it starts no issuer HTTP service or workers.
type Provider struct {
	config       Config
	db           *sqlitedb.Database
	binding      [32]byte
	callback     string
	callbackPath string
	host         string
	cookieName   string
}

// New opens a configured provider. Pending state survives compatible restarts.
func New(ctx context.Context, config *Config) (*Provider, error) {
	if config == nil {
		return nil, ErrInvalid
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, _ := json.Marshal([]string{c.Name, c.Realm, c.PublicOrigin, c.BasePath, c.IssuerURL, c.CookieName})
	binding := sha256.Sum256(data)
	db, err := sqlitedb.Open(ctx, c.Path, c.Timeout, 1094931288, map[string]string{"tickets": "CREATE TABLE tickets (request BLOB PRIMARY KEY, binding BLOB NOT NULL, browser BLOB NOT NULL, expires INTEGER NOT NULL, ticket BLOB, ticket_expires INTEGER NOT NULL, identity BLOB)"})
	if err != nil {
		return nil, err
	}
	origin, _ := url.Parse(c.PublicOrigin)
	callbackPath := strings.TrimSuffix(c.BasePath, "/") + "/provider/" + c.Realm
	return &Provider{config: c, db: db, binding: binding, callback: c.PublicOrigin + callbackPath, callbackPath: callbackPath, host: origin.Host, cookieName: c.CookieName}, nil
}
func secret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func validSecret(value string) bool {
	data, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == value
}
func (p *Provider) cookie(value string, remove bool) *http.Cookie {
	c := &http.Cookie{Name: p.cookieName, Value: value, Path: p.callbackPath, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300, Expires: time.Now().Add(5 * time.Minute)}
	if remove {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	return c
}

// CallbackURL returns the pinned destination for the trusted issuer's redirect.
// The issuer must not accept an arbitrary callback supplied by its HTTP caller.
func (p *Provider) CallbackURL() string { return p.callback }

// Login begins a browser-bound request or atomically consumes its issued ticket.
// Only canonical HTTPS GETs are accepted. The caller must not publish the result
// on error; the portal supplies no-store and no-referrer response headers.
func (p *Provider) Login(ctx context.Context, r *http.Request) (*idp.HTTPLoginResult, error) {
	if p == nil || p.db == nil {
		return nil, ErrUnavailable
	}
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.TLS == nil || r.Host != p.host || r.URL.Path != p.callbackPath || r.URL.EscapedPath() != p.callbackPath || (r.URL.Scheme != "" && r.URL.Scheme != "https") || r.URL.Fragment != "" || len(r.URL.RawQuery) > 1024 {
		return nil, ErrDenied
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, ErrDenied
	}
	if r.URL.RawQuery == "" && !r.URL.ForceQuery {
		return p.begin(ctx)
	}
	if len(values) != 2 || len(values["state"]) != 1 || len(values["ticket"]) != 1 || !validSecret(values.Get("state")) || !validSecret(values.Get("ticket")) {
		return nil, ErrDenied
	}
	var browser string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == p.cookieName {
			browser = cookie.Value
			count++
		}
	}
	if count != 1 || !validSecret(browser) {
		return nil, ErrDenied
	}
	requestDigest := sha256.Sum256([]byte(values.Get("state")))
	ticketDigest := sha256.Sum256([]byte(values.Get("ticket")))
	browserDigest := sha256.Sum256([]byte(browser))
	var identity idp.LoginIdentity
	err = p.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var storedBrowser, storedTicket, payload []byte
		var expires, ticketExpires int64
		err := tx.QueryRowContext(ctx, "SELECT browser,ticket,identity,expires,ticket_expires FROM tickets WHERE request=? AND binding=?", requestDigest[:], p.binding[:]).Scan(&storedBrowser, &storedTicket, &payload, &expires, &ticketExpires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if expires <= now || ticketExpires <= now || subtle.ConstantTimeCompare(storedBrowser, browserDigest[:]) != 1 || subtle.ConstantTimeCompare(storedTicket, ticketDigest[:]) != 1 {
			return ErrDenied
		}
		if len(payload) > 8192 || json.Unmarshal(payload, &identity) != nil || identity.Validate() != nil {
			return ErrUnavailable
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM tickets WHERE request=?", requestDigest[:])
		return err
	})
	if err != nil {
		return nil, err
	}
	return &idp.HTTPLoginResult{Identity: &identity, Cookie: p.cookie("", true)}, nil
}
func (p *Provider) begin(ctx context.Context) (*idp.HTTPLoginResult, error) {
	request, browser := secret(), secret()
	requestDigest := sha256.Sum256([]byte(request))
	browserDigest := sha256.Sum256([]byte(browser))
	err := p.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "DELETE FROM tickets WHERE expires<=?", now); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM tickets").Scan(&count); err != nil {
			return err
		}
		if count >= 1024 {
			return ErrFull
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO tickets VALUES(?,?,?,?,NULL,0,NULL)", requestDigest[:], p.binding[:], browserDigest[:], now+300)
		return err
	})
	if err != nil {
		return nil, err
	}
	issuer, _ := url.Parse(p.config.IssuerURL)
	values := url.Values{"request": {request}, "callback": {p.callback}}
	issuer.RawQuery = values.Encode()
	return &idp.HTTPLoginResult{RedirectURL: issuer.String(), Cookie: p.cookie(browser, false)}, nil
}

// Issue authenticates through a trusted application's decision, not an HTTP
// endpoint. Call only after authenticating that application's user. It binds a
// short-lived ticket to an existing browser request and snapshots the identity.
// An uncertain return publishes no ticket; start a fresh login after reconciliation.
func (p *Provider) Issue(ctx context.Context, request string, identity *idp.LoginIdentity) (string, error) {
	if p == nil || p.db == nil {
		return "", ErrUnavailable
	}
	if !validSecret(request) || identity.Validate() != nil {
		return "", ErrInvalid
	}
	data, err := json.Marshal(identity)
	if err != nil || len(data) > 8192 {
		return "", ErrInvalid
	}
	ticket := secret()
	ticketDigest := sha256.Sum256([]byte(ticket))
	requestDigest := sha256.Sum256([]byte(request))
	err = p.db.Write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var expires int64
		var previous []byte
		err := tx.QueryRowContext(ctx, "SELECT expires,ticket FROM tickets WHERE request=? AND binding=?", requestDigest[:], p.binding[:]).Scan(&expires, &previous)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if expires <= now || len(previous) != 0 {
			return ErrDenied
		}
		_, err = tx.ExecContext(ctx, "UPDATE tickets SET ticket=?,identity=?,ticket_expires=? WHERE request=?", ticketDigest[:], data, min(expires, now+120), requestDigest[:])
		return err
	})
	if err != nil {
		return "", err
	}
	return ticket, nil
}

// GetName returns the configured instance name.
func (p *Provider) GetName() string { return p.config.Name }

// GetRealm returns the configured authentication realm.
func (p *Provider) GetRealm() string { return p.config.Realm }

// GetKind distinguishes ticket federation from password identity stores.
func (p *Provider) GetKind() string { return "sqlite-ticket" }

// GetDriver identifies the trusted-application ticket protocol.
func (p *Provider) GetDriver() string { return "ticket" }

// GetConfig exposes identifiers without issuer URLs, paths or credentials.
func (p *Provider) GetConfig() map[string]any {
	return map[string]any{"name": p.config.Name, "realm": p.config.Realm, "kind": p.GetKind()}
}

// Configure checks the current database without changing configuration.
func (p *Provider) Configure() error {
	if p == nil || p.db == nil {
		return ErrUnavailable
	}
	return p.db.Read(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		var count int
		return tx.QueryRowContext(ctx, "SELECT count(*) FROM tickets").Scan(&count)
	})
}

// Configured reports whether the current handle is available for portal injection.
func (p *Provider) Configured() bool { return p != nil && p.Configure() == nil }

// Request rejects legacy protocol dispatch; Login owns this protocol.
func (p *Provider) Request(operator.Type, *requests.Request) error { return ErrDenied }

// GetLoginIcon returns detached portal login metadata.
func (p *Provider) GetLoginIcon() *icons.LoginIcon {
	icon := icons.NewLoginIcon("ticket")
	icon.SetRealm(p.config.Realm)
	icon.SetEndpoint("provider/" + p.config.Realm)
	icon.Text = "Application sign-in"
	return icon
}

// GetLogoutURL returns no upstream logout endpoint.
func (p *Provider) GetLogoutURL() string { return "" }

// GetLoginCookieName returns the independently configured browser-binding name.
func (p *Provider) GetLoginCookieName() string { return p.config.CookieName }

// GetIdentityTokenCookieName returns no upstream identity-token cookie.
func (p *Provider) GetIdentityTokenCookieName() string { return "" }

// Close closes only this handle; durable pending requests survive restart.
func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	return p.db.Close()
}

var _ idp.IdentityProvider = (*Provider)(nil)
var _ idp.HTTPLoginProvider = (*Provider)(nil)
