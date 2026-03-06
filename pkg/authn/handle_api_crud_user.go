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
	"encoding/json"
	"time"

	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

type userCrudRequest struct {
	Realm     string         `json:"realm"`
	Operation string         `json:"operation"`
	User      map[string]any `json:"user"`
}

func (p *Portal) handleAPICrudUser(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	req := &userCrudRequest{}
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			p.logger.Error(
				"failed to decode request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/user"),
				zap.String("error", err.Error()),
			)
			return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		}
	}

	if req.Realm == "" {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/user"),
			zap.String("error", "missing realm"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	if req.Operation == "" {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/user"),
			zap.String("error", "missing operation"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	validOps := map[string]bool{
		"info":            true,
		"add":             true,
		"delete":          true,
		"disable":         true,
		"enable":          true,
		"reset_password":  true,
		"overwrite_roles": true,
		"add_roles":       true,
	}

	if !validOps[req.Operation] {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("operation", req.Operation),
			zap.String("api_endpoint", "server/user"),
			zap.String("error", "invalid operation"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	var username, emailAddress string

	if req.User != nil {
		if v, ok := req.User["username"].(string); ok {
			username = v
		}
		if v, ok := req.User["email"].(string); ok {
			emailAddress = v
		}
	}

	if username == "" || emailAddress == "" {
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/user"),
			zap.String("error", "either username or email address are missing"),
		)
		return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	var resp map[string]any
	for _, ids := range p.identityStores {
		if ids.GetRealm() != req.Realm {
			continue
		}
		var err error

		switch req.Operation {
		case "info":
			resp, err = ids.FetchUserData(username, emailAddress)
			if err != nil {
				p.logger.Warn(
					"failed to fetch user data",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			}
		case "delete":
			resp = make(map[string]any)
			if err := ids.DeleteUser(username, emailAddress); err != nil {
				p.logger.Warn(
					"failed to delete user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"deleted user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
		case "disable":
			resp = make(map[string]any)
			if err := ids.DisableUser(username, emailAddress); err != nil {
				p.logger.Warn(
					"failed to disable user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"disabled user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
		case "enable":
			resp = make(map[string]any)
			if err := ids.EnableUser(username, emailAddress); err != nil {
				p.logger.Warn(
					"failed to enable user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"enabled user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

		case "reset_password":
			resp, err = ids.ResetUserPassword(username, emailAddress)
			if err != nil {
				resp = make(map[string]any)
				p.logger.Warn(
					"failed to reset user password",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"resetting user password complete",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
		case "add":
			var name string
			var roles []string

			if req.User != nil {
				if v, ok := req.User["name"].(string); ok {
					name = v
				}
				if v, ok := req.User["roles"].([]any); ok {
					for _, role := range v {
						if s, ok := role.(string); ok {
							roles = append(roles, s)
						}
					}
				}
			}
			if name == "" {
				p.logger.Warn(
					"malformed request",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.String("error", "name is missing"),
				)
				return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			}

			if len(roles) < 1 {
				p.logger.Warn(
					"malformed request",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.String("error", "roles are missing"),
				)
				return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			}

			resp, err = ids.AddUser(username, emailAddress, name, roles)
			if err != nil {
				p.logger.Warn(
					"failed to add user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp = make(map[string]any)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"added user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

		case "overwrite_roles", "add_roles":
			var roles []string
			if req.User != nil {
				if v, ok := req.User["roles"].([]any); ok {
					for _, role := range v {
						if s, ok := role.(string); ok {
							roles = append(roles, s)
						}
					}
				}
			}
			if len(roles) < 1 {
				p.logger.Warn(
					"malformed request",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.String("error", "roles are missing"),
				)
				return p.handleJSONError(ctx, w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			}

			if req.Operation == "overwrite_roles" {
				resp, err = ids.OverwriteUserRoles(username, emailAddress, roles)
			} else {
				resp, err = ids.AddUserRoles(username, emailAddress, roles)
			}
			if err != nil {
				p.logger.Warn(
					"user operation failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("operation", req.Operation),
					zap.String("api_endpoint", "server/user"),
					zap.Error(err),
				)
				resp = make(map[string]any)
				resp["status"] = "failure"
				resp["error"] = err.Error()
			} else {
				resp["status"] = "success"
				p.logger.Debug(
					"deleted user",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("api_endpoint", "server/user"),
					zap.String("realm", req.Realm),
					zap.String("operation", req.Operation),
					zap.String("username", username),
					zap.String("email", emailAddress),
				)
			}
			resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

		default:
			p.logger.Warn(
				"operation not implemented",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "server/user"),
			)
			return p.handleJSONError(ctx, w, http.StatusNotImplemented, http.StatusText(http.StatusNotImplemented))
		}
		break
	}

	if resp == nil {
		resp := make(map[string]any)
		resp["error"] = "not found"
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		p.logger.Error(
			"failed to encode response",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "server/user"),
			zap.String("error", err.Error()),
		)
		return p.handleJSONError(ctx, w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	return nil
}
