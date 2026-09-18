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

package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type portalHandler struct {
	routes   []PortalRoute
	portals  map[string]*authn.Portal
	logger   *zap.Logger
	mu       sync.Mutex
	stopping bool
	active   sync.WaitGroup
}

// Serve owns listener immediately, including on configuration failure. It
// constructs an AuthCrunch runtime from a fresh security configuration graph,
// serves until ctx is canceled or the listener fails, drains requests, and
// closes the runtime. Cancellation after a successful drain returns nil.
// The caller must not mutate either configuration while Serve is running.
// HTTPS uses supplied PEM files with TLS 1.2 or newer; certificate renewal takes
// effect on restart. No forwarding headers or proxy protocol are trusted.
// Runtime initialization errors have a redacted message. Their wrapped cause
// remains available through errors.Unwrap for private diagnostics and may
// contain credentials; do not log it to a shared sink.
func Serve(ctx context.Context, listener net.Listener, cfg *Config, security *authcrunch.Config, logger *zap.Logger) (err error) {
	if listener == nil {
		return fmt.Errorf("HTTP listener is required")
	}
	defer listener.Close()
	if ctx == nil {
		return fmt.Errorf("HTTP server context is required")
	}
	if logger == nil {
		return fmt.Errorf("HTTP server logger is required")
	}
	if cfg == nil {
		return fmt.Errorf("HTTP server configuration is required")
	}
	config := *cfg
	config.Portals = append([]PortalRoute(nil), cfg.Portals...)
	if err := config.Validate(); err != nil {
		return err
	}
	if err := validateSecurity(&config, security); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if !config.InsecureHTTP {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load HTTP server TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	}
	runtime, err := authcrunch.NewServer(security, logger)
	if err != nil {
		return &initializationError{cause: err}
	}
	defer func() { err = errors.Join(err, runtime.Close()) }()
	handler := &portalHandler{routes: config.Portals, portals: make(map[string]*authn.Portal), logger: logger}
	for _, route := range config.Portals {
		portal, err := runtime.GetPortalByName(route.Name)
		if err != nil {
			return fmt.Errorf("resolve HTTP portal: %w", err)
		}
		handler.portals[route.Name] = portal
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: duration(config.ReadHeaderTimeout),
		ReadTimeout:       duration(config.ReadTimeout),
		WriteTimeout:      duration(config.WriteTimeout),
		IdleTimeout:       duration(config.IdleTimeout),
		MaxHeaderBytes:    config.MaxHeaderBytes,
		ErrorLog:          zap.NewStdLog(logger),
	}
	return serve(ctx, listener, server, handler, duration(config.ShutdownTimeout), logger)
}

func duration(value string) time.Duration {
	parsed, _ := time.ParseDuration(value) // Config.Validate has checked every value.
	return parsed
}

func serve(ctx context.Context, listener net.Listener, server *http.Server, handler *portalHandler, timeout time.Duration, logger *zap.Logger) error {
	// Request contexts survive the signal so accepted work can drain. Forced
	// shutdown cancels them before awaiting handlers and disposing the runtime.
	requestContext, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	server.BaseContext = func(net.Listener) context.Context { return requestContext }
	finished := make(chan error, 1)
	tlsEnabled := server.TLSConfig != nil
	go func() {
		if tlsEnabled {
			finished <- server.ServeTLS(listener, "", "")
		} else {
			finished <- server.Serve(listener)
		}
	}()
	scheme := "https"
	if !tlsEnabled {
		scheme = "http"
	}
	logger.Info("authdb listening", zap.String("address", listener.Addr().String()), zap.String("scheme", scheme))
	var serveErr error
	received := false
	select {
	case <-ctx.Done():
	case serveErr = <-finished:
		received = true
	}
	handler.mu.Lock()
	handler.stopping = true
	handler.mu.Unlock()
	shutdownContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	if shutdownErr != nil {
		cancelRequests()
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	handler.active.Wait()
	if !received {
		serveErr = <-finished
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, shutdownErr)
}

func (h *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	h.active.Add(1)
	h.mu.Unlock()
	defer h.active.Done()
	// Keep routing literal: do not clean, decode separators, or redirect a
	// malformed path into a different portal's namespace.
	if r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\\x00") || path.Clean(r.URL.Path) != strings.TrimSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	for _, route := range h.routes {
		if !containsPath(route.Path, r.URL.Path) {
			continue
		}
		// Clone before removing headers so an embedding caller retains its
		// request. AuthCrunch's URL and client-address helpers consume these.
		r = r.Clone(r.Context())
		for key := range r.Header {
			lower := strings.ToLower(key)
			if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
				delete(r.Header, key)
			}
		}
		if r.URL.Path == route.Path || r.URL.Path == route.Path+"/" {
			target := strings.TrimSuffix(route.Path, "/") + "/login"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}
		response := &responseWriter{ResponseWriter: w}
		if err := h.portals[route.Name].ServeHTTP(r.Context(), response, r, requests.NewRequest()); err != nil {
			// Handler errors may contain credential-bearing request data.
			h.logger.Error("authdb portal request failed", zap.String("portal", route.Name))
			if !response.written {
				http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
		return
	}
	http.NotFound(w, r)
}

type responseWriter struct {
	http.ResponseWriter
	written bool
}

func (w *responseWriter) WriteHeader(status int) {
	if status >= 200 {
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseWriter) Write(data []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(data)
}
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func validateSecurity(cfg *Config, security *authcrunch.Config) error {
	if security == nil {
		return fmt.Errorf("security configuration is required")
	}
	if err := validateConfigurationObjects(security); err != nil {
		return err
	}
	// The root API expects concrete entries and string realms. Reject malformed
	// serialized graphs at this new consumer boundary before runtime setup.
	for _, entry := range security.IdentityStores {
		if realm, ok := entry.Params["realm"]; ok {
			if _, ok := realm.(string); !ok {
				return fmt.Errorf("identity store realm must be a string")
			}
		}
	}
	for _, entry := range security.IdentityProviders {
		if realm, ok := entry.Params["realm"]; ok {
			if _, ok := realm.(string); !ok {
				return fmt.Errorf("identity provider realm must be a string")
			}
		}
	}
	for _, entry := range security.AuthorizationPolicies {
		if err := validateCryptoStatements(entry.RawCryptoKeyStoreConfig); err != nil {
			return err
		}
	}
	portals := make(map[string]*authn.PortalConfig)
	for _, entry := range security.AuthenticationPortals {
		if err := validateCryptoStatements(entry.RawCryptoKeyStoreConfig); err != nil {
			return err
		}
		if portals[entry.Name] != nil {
			return fmt.Errorf("duplicate authentication portal name")
		}
		portals[entry.Name] = entry
	}
	for i, route := range cfg.Portals {
		portal := portals[route.Name]
		if portal == nil {
			return fmt.Errorf("portal route %d references an unknown authentication portal", i+1)
		}
		if portal.RefreshTokens != nil && portal.RefreshTokens.Enabled && strings.TrimSuffix(portal.RefreshTokens.BasePath, "/") != strings.TrimSuffix(route.Path, "/") {
			return fmt.Errorf("portal route %d does not match the refresh base path", i+1)
		}
		if portal.OIDCProvider != nil && portal.OIDCProvider.Enabled {
			issuer, err := url.Parse(portal.OIDCProvider.Issuer)
			if err != nil || strings.TrimSuffix(issuer.Path, "/") != strings.TrimSuffix(route.Path, "/") {
				return fmt.Errorf("portal route %d does not match the OIDC issuer path", i+1)
			}
		}
		if cfg.InsecureHTTP && ((portal.RefreshTokens != nil && portal.RefreshTokens.Enabled) || (portal.OIDCProvider != nil && portal.OIDCProvider.Enabled)) {
			return fmt.Errorf("refresh and OIDC portals require HTTPS")
		}
	}
	return nil
}
