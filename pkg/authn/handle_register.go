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

package authn

import (
	"context"
	"github.com/greenpau/go-authcrunch/pkg/authn/validators"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
	"net/http"
	"path"
	"strings"
	"time"
)

type registerRequest struct {
	view           string
	message        string
	registrationID string
}

func (p *Portal) handleHTTPRegister(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	if rr.Response.Authenticated {
		// Authenticated users are not allowed to register.
		return p.handleHTTPRedirect(ctx, w, r, rr, "/portal")
	}

	if strings.Contains(r.URL.Path, "/register/ack/") {
		if r.Method != "POST" {
			// Handle registration acknowledgement.
			return p.handleHTTPRegisterAck(ctx, w, r, rr)
		}
		// Handle registration acknowledgement page.
		return p.handleHTTPRegisterAckRequest(ctx, w, r, rr)
	}

	if r.Method != "POST" {
		// Handle registration landing page.
		return p.handleHTTPRegisterScreen(ctx, w, r, rr)
	}
	// Handle registration request.
	return p.handleHTTPRegisterRequest(ctx, w, r, rr)
}

func (p *Portal) handleHTTPRegisterScreen(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	reg := &registerRequest{
		view: "register",
	}
	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
}

func (p *Portal) handleHTTPRegisterScreenWithMessage(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, reg *registerRequest) error {
	if len(p.config.UserRegistries) < 1 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusServiceUnavailable)
	}

	resp := p.ui.GetArgs()
	resp.BaseURL(rr.Upstream.BasePath)
	resp.Data["view"] = reg.view

	switch reg.view {
	case "register":
		resp.PageTitle = p.userRegistry.GetTitle()
		if p.userRegistry.GetRequireAcceptTerms() {
			resp.Data["require_accept_terms"] = true
		}

		if p.userRegistry.GetCode() != "" {
			resp.Data["require_registration_code"] = true
		}

		if p.userRegistry.GetTermsConditionsLink() != "" {
			resp.Data["terms_conditions_link"] = p.userRegistry.GetTermsConditionsLink()
		} else {
			resp.Data["terms_conditions_link"] = path.Join(rr.Upstream.BasePath, "/terms-and-conditions")
		}

		if p.userRegistry.GetPrivacyPolicyLink() != "" {
			resp.Data["privacy_policy_link"] = p.userRegistry.GetPrivacyPolicyLink()
		} else {
			resp.Data["privacy_policy_link"] = path.Join(rr.Upstream.BasePath, "/privacy-policy")
		}

		resp.Data["username_validate_pattern"] = p.userRegistry.GetUsernamePolicyRegex()
		resp.Data["username_validate_title"] = p.userRegistry.GetUsernamePolicySummary()
		resp.Data["password_validate_pattern"] = p.userRegistry.GetPasswordPolicyRegex()
		resp.Data["password_validate_title"] = p.userRegistry.GetPasswordPolicySummary()
		if reg.message != "" {
			resp.Message = reg.message
		}
	case "registered":
		resp.PageTitle = "Thank you!"
	case "ackfail":
		resp.PageTitle = "Registration"
		resp.Data["message"] = reg.message
	case "ack":
		resp.PageTitle = "Registration"
		resp.Data["registration_id"] = reg.registrationID
	case "acked":
		resp.PageTitle = "Registration"
	}

	content, err := p.ui.Render("register", resp)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func (p *Portal) handleHTTPRegisterRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var message string
	var maxBytesLimit int64 = 1000
	var minBytesLimit int64 = 15
	var userHandle, userMail, userSecret, userCode string
	var violations []string
	var userAccept, validUserRegistration bool
	validUserRegistration = true

	if r.ContentLength > maxBytesLimit || r.ContentLength < minBytesLimit {
		violations = append(violations, "payload size")
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		violations = append(violations, "content type")
	}

	if len(violations) > 0 {
		message = "Registration request is non compliant"
		p.logger.Warn(
			message,
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Int64("min_size", minBytesLimit),
			zap.Int64("max_size", maxBytesLimit),
			zap.String("content_type", r.Header.Get("Content-Type")),
			zap.Int64("size", r.ContentLength),
			zap.Strings("violations", violations),
		)
		reg := &registerRequest{view: "register", message: message}
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	if err := r.ParseForm(); err != nil {
		p.logger.Warn(
			"failed parsing submitted registration form",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("src_ip", addrutil.GetSourceAddress(r)),
			zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
			zap.String("error", err.Error()),
		)
		message = "Failed processing the registration form"
		validUserRegistration = false
	} else {
		for k, v := range r.Form {
			switch k {
			case "registrant":
				userHandle = v[0]
			case "registrant_password":
				userSecret = v[0]
			case "registrant_email":
				userMail = v[0]
			case "registrant_code":
				userCode = v[0]
			case "accept_terms":
				if v[0] == "on" {
					userAccept = true
				}
			}
		}
	}

	if validUserRegistration {
		// Inspect registration values.
		if p.userRegistry.GetCode() != "" {
			if userCode != p.userRegistry.GetCode() {
				validUserRegistration = false
				message = "Failed processing the registration form due to invalid verification code"
			}
		}

		if p.userRegistry.GetRequireAcceptTerms() {
			if !userAccept {
				validUserRegistration = false
				message = "Failed processing the registration form due to the failure to accept terms and conditions"
			}
		}

		for _, k := range []string{"username", "password", "email"} {
			if !validUserRegistration {
				break
			}
			switch k {
			case "username":
				handleOpts := make(map[string]interface{})
				if err := validators.ValidateUserInput("handle", userHandle, handleOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "password":
				secretOpts := make(map[string]interface{})
				if err := validators.ValidateUserInput("secret", userSecret, secretOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			case "email":
				emailOpts := make(map[string]interface{})
				if p.userRegistry.GetRequireDomainMailRecord() {
					emailOpts["check_domain_mx"] = true
				}
				if err := validators.ValidateUserInput(k, userMail, emailOpts); err != nil {
					validUserRegistration = false
					message = "Failed processing the registration form due " + err.Error()
				}
			}
		}
	}

	if validUserRegistration {
		registrationID := util.GetRandomStringFromRange(64, 96)
		registrationCode := util.GetRandomStringFromRange(6, 8)
		cachedEntry := map[string]string{
			"username":          userHandle,
			"password":          userSecret,
			"email":             userMail,
			"registration_code": registrationCode,
		}
		if err := p.userRegistry.AddRegistrationEntry(registrationID, cachedEntry); err != nil {
			p.logger.Warn(
				"failed adding a record to registration cache",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			message = "Internal registration error"
			validUserRegistration = false
		} else {
			p.logger.Debug(
				"Created registration cache entry",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("registration_id", registrationID),
			)

			// Send notification about registration.
			regData := map[string]string{
				"template":          "registration_confirmation",
				"session_id":        rr.Upstream.SessionID,
				"request_id":        rr.ID,
				"registration_id":   registrationID,
				"registration_code": registrationCode,
				"username":          userHandle,
				"email":             userMail,
			}

			regURL, err := addrutil.GetCurrentURLWithSuffix(r, "/register")
			if err != nil {
				p.logger.Warn(
					"Detected malformed request headers",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Error(err),
				)
			}
			regData["registration_url"] = regURL

			regData["src_ip"] = addrutil.GetSourceAddress(r)
			regData["src_conn_ip"] = addrutil.GetSourceConnAddress(r)
			regData["timestamp"] = time.Now().UTC().Format(time.UnixDate)
			if err := p.userRegistry.Notify(regData); err != nil {
				p.logger.Warn(
					"Failed to send notification",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("registration_id", registrationID),
					zap.String("registration_type", "registration_confirmation"),
					zap.Error(err),
				)
				p.userRegistry.DeleteRegistrationEntry(registrationID)
				message = "Internal registration messaging error"
				validUserRegistration = false
			}
		}
	}

	if !validUserRegistration {
		p.logger.Warn(
			"failed registration",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("src_ip", addrutil.GetSourceAddress(r)),
			zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
			zap.String("error", message),
		)
		reg := &registerRequest{view: "register", message: message}
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	p.logger.Info("Successful user registration",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("username", userHandle),
		zap.String("email", userMail),
		zap.String("src_ip", addrutil.GetSourceAddress(r)),
		zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
	)
	reg := &registerRequest{view: "registered"}
	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
}

func (p *Portal) handleHTTPRegisterAck(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	reg := &registerRequest{
		view: "ackfail",
	}
	registrationID, err := getEndpointKeyID(r.URL.Path, "/register/ack/")
	if err != nil {
		reg.message = "Malformed registration acknowledgement request"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	if _, err := p.userRegistry.GetRegistrationEntry(registrationID); err != nil {
		reg.message = "Registration identifier not found"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	reg.view = "ack"
	reg.registrationID = registrationID

	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
}

func (p *Portal) handleHTTPRegisterAckRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	reg := &registerRequest{
		view: "ackfail",
	}

	if err := r.ParseForm(); err != nil {
		p.logger.Warn(
			"failed parsing registration acknowledgement form",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("src_ip", addrutil.GetSourceAddress(r)),
			zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
			zap.String("error", err.Error()),
		)
		reg.message = "Failed processing the registration acknowledgement form"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	registrationCode := strings.TrimSpace(r.FormValue("registration_code"))

	registrationID, err := getEndpointKeyID(r.URL.Path, "/register/ack/")
	if err != nil {
		reg.message = "Malformed registration acknowledgement request"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	usr, err := p.userRegistry.GetRegistrationEntry(registrationID)
	if err != nil {
		reg.message = "Registration identifier not found"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	if usr["registration_code"] != registrationCode {
		p.logger.Warn(
			"failed registration acknowledgement due to registration code mismatch",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("src_ip", addrutil.GetSourceAddress(r)),
			zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
		)
		reg.message = "Registration identifier mismatch"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	// Build registration commit request.
	req := &requests.Request{
		User: requests.User{
			Username: usr["username"],
			Password: usr["password"],
			Email:    usr["email"],
			Roles:    []string{"authp/user"},
		},
		Query: requests.Query{
			ID: registrationID,
		},
	}

	if err := p.userRegistry.DeleteRegistrationEntry(registrationID); err != nil {
		reg.message = "Registration session terminated"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	if err := p.userRegistry.AddUser(req); err != nil {
		p.logger.Warn(
			"registration request backend erred",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		reg.message = "Registration session is no longer valid"
		return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
	}

	// Send a notification to admins.
	regData := map[string]string{
		"template":        "registration_ready",
		"session_id":      rr.Upstream.SessionID,
		"request_id":      rr.ID,
		"registration_id": registrationID,
		"username":        req.User.Username,
		"email":           req.User.Email,
	}

	regURL, err := addrutil.GetCurrentURLWithSuffix(r, "/register")
	if err != nil {
		p.logger.Warn(
			"Detected malformed request headers",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
	}
	regData["registration_url"] = regURL

	regData["src_ip"] = addrutil.GetSourceAddress(r)
	regData["src_conn_ip"] = addrutil.GetSourceConnAddress(r)
	regData["timestamp"] = time.Now().UTC().Format(time.UnixDate)

	if err := p.userRegistry.Notify(regData); err != nil {
		p.logger.Warn(
			"Failed to send notification",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("registration_id", registrationID),
			zap.String("registration_type", "registration_ready"),
			zap.Error(err),
		)
	}

	reg.view = "acked"
	return p.handleHTTPRegisterScreenWithMessage(ctx, w, r, rr, reg)
}
