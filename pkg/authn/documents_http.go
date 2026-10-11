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

package authn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const documentsJSONLimit = 64 << 10
const documentsBodyLimit = documentsJSONLimit + (documents.ChunkSize+16)*4/3 + 1

type documentsCommand struct {
	operation  string
	ID         string             `json:"id"`
	UserID     string             `json:"user_id"`
	KeyID      string             `json:"key_id"`
	After      string             `json:"after"`
	Idx        int                `json:"idx"`
	Size       int64              `json:"size"`
	Chunks     int                `json:"chunks"`
	Ciphertext string             `json:"ciphertext"`
	Key        documents.Key      `json:"key"`
	Manifest   documents.Manifest `json:"manifest"`
	Envelope   documents.Envelope `json:"envelope"`
	data       []byte
}

// Parse exact operation payloads before taking any identity/storage locks. A
// body cannot silently carry fields for a different operation. The route is
// authoritative; the client cannot override it in the request body.
func parseDocumentsPayload(command documentsCommand, body []byte) (documentsCommand, int) {
	operation := command.operation
	var fields string
	switch operation {
	case "key.reset":
		fields = "user_id key_id"
	case "key.register":
		fields = "key"
	case "file.allocate":
		fields = "size chunks"
	case "file.manifest":
		fields = "manifest"
	case "chunk.put":
		fields = "ciphertext"
	case "share.put":
		fields = "envelope"
	default:
		return command, 400
	}
	if operation != "chunk.put" && len(body) > documentsJSONLimit {
		return command, 413
	}
	var payload map[string]json.RawMessage
	if err := decodeDocumentsJSON(body, &payload); err != nil || payload == nil {
		return command, 400
	}
	required := strings.Fields(fields)
	for _, name := range required {
		if _, ok := payload[name]; !ok {
			return command, 400
		}
	}
	for name, value := range payload {
		if !slices.Contains(required, name) || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return command, 400
		}
	}
	if err := decodeDocumentsJSON(body, &command); err != nil {
		return command, 400
	}
	if slices.Contains(required, "user_id") && !documents.ValidUserID(command.UserID) {
		return command, 400
	}
	if slices.Contains(required, "key_id") && !documents.ValidID(command.KeyID) {
		return command, 400
	}
	if operation == "chunk.put" {
		if len(command.Ciphertext) > base64.RawURLEncoding.EncodedLen(documents.ChunkSize+16) {
			return command, 413
		}
		data, err := base64.RawURLEncoding.Strict().DecodeString(command.Ciphertext)
		if err != nil || len(data) < 16 || base64.RawURLEncoding.EncodeToString(data) != command.Ciphertext {
			return command, 400
		}
		command.data = data
	}
	return command, 200
}

func documentsStatus(err error) int {
	switch {
	case errors.Is(err, documents.ErrInvalid):
		return http.StatusBadRequest
	case errors.Is(err, documents.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, documents.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, documents.ErrQuota):
		return http.StatusInsufficientStorage
	case errors.Is(err, documents.ErrIdentityConflict):
		return http.StatusForbidden
	case errors.Is(err, identity.ErrRefreshIdentityDenied):
		return http.StatusUnauthorized
	default:
		return http.StatusServiceUnavailable
	}
}

func writeDocumentsJSON(w http.ResponseWriter, rr *requests.Request, code int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	rr.Response.Code = code
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(value)
}

// Match only canonical operation paths; never normalize aliases, dot segments,
// extra descendants or encoded separators into an authorized action.
func documentsRoute(path, rawPath, basePath string) (documentsCommand, int) {
	var command documentsCommand
	prefix := strings.TrimSuffix(basePath, "/") + "/api/documents/"
	if rawPath != "" || !strings.HasPrefix(path, prefix) {
		return command, http.StatusNotFound
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	switch {
	case len(parts) == 1 && parts[0] == "bootstrap":
		command.operation = "bootstrap"
	case len(parts) == 2 && parts[0] == "keys" && slices.Contains([]string{"fetch", "register", "reset"}, parts[1]):
		command.operation = "key." + parts[1]
	case len(parts) == 3 && parts[0] == "key" && parts[2] == "lookup":
		command.operation, command.UserID = "key.lookup", parts[1]
	case len(parts) == 1 && parts[0] == "files":
		command.operation = "file.list"
	case len(parts) == 2 && parts[0] == "files" && parts[1] == "allocate":
		command.operation = "file.allocate"
	case len(parts) == 3 && parts[0] == "file" && slices.Contains([]string{"manifest", "commit", "fetch", "delete"}, parts[2]):
		command.operation, command.ID = "file."+parts[2], parts[1]
	case len(parts) == 5 && parts[0] == "file" && parts[2] == "chunk" && slices.Contains([]string{"put", "fetch"}, parts[4]):
		command.operation, command.ID = "chunk."+parts[4], parts[1]
		idx, err := strconv.Atoi(parts[3])
		if err != nil || idx < 0 || idx >= 4096 || strconv.Itoa(idx) != parts[3] {
			return command, http.StatusBadRequest
		}
		command.Idx = idx
	case len(parts) == 4 && parts[0] == "file" && parts[2] == "share" && parts[3] == "list":
		command.operation, command.ID = "share.list", parts[1]
	case len(parts) == 5 && parts[0] == "file" && parts[2] == "share" && slices.Contains([]string{"put", "delete"}, parts[4]):
		command.operation, command.ID, command.UserID = "share."+parts[4], parts[1], parts[3]
	default:
		return command, http.StatusNotFound
	}
	if parts[0] == "file" && len(parts) >= 3 && !documents.ValidID(command.ID) {
		return command, http.StatusBadRequest
	}
	if (command.operation == "key.lookup" || command.operation == "share.put" || command.operation == "share.delete") && !documents.ValidUserID(command.UserID) {
		return command, http.StatusBadRequest
	}
	return command, http.StatusOK
}

func documentsOperationMethod(operation string) string {
	switch operation {
	case "bootstrap", "key.fetch", "key.lookup", "file.list", "file.fetch", "chunk.fetch", "share.list":
		return http.MethodGet
	case "key.register", "file.manifest", "chunk.put", "share.put":
		return http.MethodPut
	case "file.delete", "share.delete":
		return http.MethodDelete
	case "file.allocate", "file.commit", "key.reset":
		return http.MethodPost
	default:
		return ""
	}
}

func documentsHasBody(operation string) bool {
	return slices.Contains([]string{"key.register", "key.reset", "file.allocate", "file.manifest", "chunk.put", "share.put"}, operation)
}

func parseDocumentsQuery(command *documentsCommand, rawQuery string, forceQuery bool) int {
	if rawQuery == "" && !forceQuery {
		return http.StatusOK
	}
	// Only the exclusive list cursor is accepted. Exact spelling prevents
	// duplicate parameters and alternate encodings from changing interpretation.
	after, ok := strings.CutPrefix(rawQuery, "after=")
	if command.operation != "file.list" || !ok || !documents.ValidID(after) {
		return http.StatusBadRequest
	}
	command.After = after
	return http.StatusOK
}

func (p *Portal) handleAPIDocuments(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	fail := func(code int) error {
		return writeDocumentsJSON(w, rr, code, map[string]any{"status": code, "message": http.StatusText(code)})
	}
	if p.documents == nil {
		return fail(http.StatusNotFound)
	}
	c := p.documentsConfig
	command, status := documentsRoute(r.URL.Path, r.URL.RawPath, c.BasePath)
	if status != http.StatusOK {
		return fail(status)
	}
	operation := command.operation
	method := documentsOperationMethod(operation)
	if r.Method != method {
		w.Header().Set("Allow", method)
		return fail(http.StatusMethodNotAllowed)
	}
	if status := parseDocumentsQuery(&command, r.URL.RawQuery, r.URL.ForceQuery); status != http.StatusOK {
		return fail(status)
	}
	origin, err := getWebAuthnExpectedOrigin(r)
	if err != nil || origin != c.PublicOrigin {
		return fail(http.StatusForbidden)
	}
	if origins := r.Header.Values("Origin"); len(origins) > 0 && (len(origins) != 1 || origins[0] != c.PublicOrigin) {
		return fail(http.StatusForbidden)
	}
	if sites := r.Header.Values("Sec-Fetch-Site"); len(sites) > 0 && (len(sites) != 1 || (sites[0] != "same-origin" && sites[0] != "none")) {
		return fail(http.StatusForbidden)
	}
	parsed, err := p.authorizeRequest(ctx, w, r, rr)
	if err != nil || parsed == nil || !rr.Response.Authenticated {
		return fail(http.StatusUnauthorized)
	}
	usr, err := p.sessions.Get(parsed.Claims.ID)
	if err != nil || usr == nil || usr.LoginEvidence.UserID == "" || usr.LoginEvidence.BackendVersion == "" || usr.LoginUsername == "" {
		return fail(http.StatusUnauthorized)
	}
	if !slices.Contains(c.Realms, usr.Authenticator.Realm) || p.authorizedRole(usr, []role.Kind{role.User, role.Admin}, true) != nil {
		return fail(http.StatusForbidden)
	}
	store := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	bound, ok := store.(refreshIdentityStore)
	if !ok || store.GetName() != usr.Authenticator.Name || usr.Authenticator.Method != "local" {
		return fail(http.StatusForbidden)
	}
	// Read the bounded body before entering the identity transaction. A slow
	// upload must not hold the account database's revocation lock.
	if len(r.Header.Values("Content-Encoding")) > 0 {
		return fail(http.StatusUnsupportedMediaType)
	}
	defer r.Body.Close()
	if documentsHasBody(operation) {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
			return fail(http.StatusUnsupportedMediaType)
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, documentsBodyLimit))
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				return fail(http.StatusRequestEntityTooLarge)
			}
			return fail(http.StatusBadRequest)
		}
		command, status = parseDocumentsPayload(command, body)
		if status != http.StatusOK {
			return fail(status)
		}
	} else {
		// GET, DELETE and commit use only their path/query parameters. Never
		// interpret a body that a client or intermediary might ignore.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			return fail(http.StatusBadRequest)
		}
	}
	userID := usr.LoginEvidence.UserID
	if !documents.ValidUserID(userID) {
		return fail(http.StatusForbidden)
	}
	var result any
	err = bound.WithRefreshIdentity(ctx, usr.LoginEvidence, func(current identity.RefreshIdentity) error {
		if current.Username != usr.LoginUsername {
			return identity.ErrRefreshIdentityDenied
		}
		if _, err := p.sessions.Get(parsed.Claims.ID); err != nil {
			return identity.ErrRefreshIdentityDenied
		}
		if err := p.documents.BindIdentity(ctx, userID, store.GetName(), store.GetRealm()); err != nil {
			return err
		}
		var err error
		result, err = p.executeDocuments(ctx, command, userID)
		return err
	})
	if err != nil {
		return fail(documentsStatus(err))
	}
	return writeDocumentsJSON(w, rr, http.StatusOK, result)
}

func decodeDocumentsJSON(body []byte, target any) error {
	if len(body) == 0 || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return documents.ErrInvalid
	}
	check := json.NewDecoder(bytes.NewReader(body))
	if err := checkDocumentsJSON(check, 0); err != nil {
		return documents.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return documents.ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return documents.ErrInvalid
	}
	return nil
}

// Reject ambiguous duplicate members (including escaped spellings), case
// aliases and excessive nesting before decoding the request fields.
func checkDocumentsJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return documents.ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return documents.ErrInvalid
	}
	seen := make(map[string]bool)
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return documents.ErrInvalid
			}
			// encoding/json also folds non-ASCII aliases, such as long s into
			// ASCII s. All protocol member names are lowercase ASCII; reject
			// every other spelling before the typed decoder can merge them.
			for _, c := range name {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
					return documents.ErrInvalid
				}
			}
			seen[name] = true
		}
		if err := checkDocumentsJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func (p *Portal) executeDocuments(ctx context.Context, command documentsCommand, userID string) (any, error) {
	s := p.documents
	var value any = map[string]bool{"success": true}
	var err error
	switch command.operation {
	case "bootstrap":
		value = map[string]any{"protocol": documents.Protocol, "portal_id": s.PortalID(), "user_id": userID, "chunk_size": documents.ChunkSize, "max_file_bytes": p.documentsConfig.MaxFileBytes, "max_user_bytes": p.documentsConfig.MaxUserBytes, "max_user_files": p.documentsConfig.MaxUserFiles, "max_recipients": p.documentsConfig.MaxRecipients, "upload_ttl_seconds": p.documentsConfig.UploadTTLSeconds}
	case "key.fetch":
		value, err = s.GetKey(ctx, userID, userID)
	case "key.reset":
		if command.UserID != userID {
			return nil, documents.ErrConflict
		}
		err = s.ResetKey(ctx, userID, command.KeyID)
	case "key.register":
		err = s.RegisterKey(ctx, userID, command.Key)
	case "key.lookup":
		var key documents.Key
		key, err = s.GetKey(ctx, userID, command.UserID)
		key.Vault = nil // Public lookup never exposes an encrypted private vault.
		value = key
	case "file.list":
		value, err = s.ListFiles(ctx, userID, command.After)
	case "file.allocate":
		value, err = s.Allocate(ctx, userID, command.Size, command.Chunks)
	case "file.fetch":
		value, err = s.GetFile(ctx, userID, command.ID)
	case "file.delete":
		err = s.Delete(ctx, userID, command.ID)
	case "file.manifest":
		err = s.PutManifest(ctx, userID, command.ID, command.Manifest)
	case "chunk.fetch":
		var data []byte
		data, err = s.GetChunk(ctx, userID, command.ID, command.Idx)
		value = map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(data)}
	case "chunk.put":
		err = s.PutChunk(ctx, userID, command.ID, command.Idx, command.data)
	case "file.commit":
		err = s.Commit(ctx, userID, command.ID)
	case "share.list":
		var recipients []string
		recipients, err = s.Recipients(ctx, userID, command.ID)
		value = map[string]any{"recipients": recipients}
	case "share.put":
		err = s.Share(ctx, userID, command.ID, command.UserID, command.Envelope)
	case "share.delete":
		err = s.Revoke(ctx, userID, command.ID, command.UserID)
	default:
		err = documents.ErrInvalid
	}
	return value, err
}
