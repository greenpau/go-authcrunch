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
	"strings"
	"testing"
)

func TestDocumentsMessageFieldNames(t *testing.T) {
	const body = `{"key":{"user_id":"00000000-0000-4000-8000-000000000002","key_id":"key","public_key":"public","vault":{"salt":"salt","nonce":"nonce","ciphertext":"ciphertext"}}}`
	if _, status := parseDocumentsPayload(documentsCommand{operation: "key.register"}, []byte(body)); status != 200 {
		t.Fatal("canonical message shape rejected")
	}
	for _, field := range []string{`"ſalt"`, `"\u017falt"`, `"Salt"`, `"salt "`, `"sält"`} {
		t.Run(field, func(t *testing.T) {
			if _, status := parseDocumentsPayload(documentsCommand{operation: "key.register"}, []byte(strings.Replace(body, `"salt":`, field+":", 1))); status != 400 {
				t.Fatal("noncanonical or ambiguous field spelling accepted")
			}
		})
	}
}

func TestDocumentsDirectPayload(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		operation, body string
		status          int
	}{
		{"file.allocate", `{"size":16,"chunks":1}`, 200},
		{"chunk.put", `{"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`, 200},
		{"file.manifest", `{"manifest":{"metadata":"ciphertext","envelope":{}}}`, 200},
		{"file.allocate", ``, 400},
		{"file.allocate", `null`, 400},
		{"file.allocate", `[]`, 400},
		{"file.allocate", `{"operation":"file.allocate","payload":{"size":16,"chunks":1}}`, 400},
		{"file.allocate", `{"size":16}`, 400},
		{"file.allocate", `{"size":null,"chunks":1}`, 400},
		{"file.allocate", `{"size":16,"chunks":1,"owner":"other"}`, 400},
		{"file.allocate", `{"size":16,"size":32,"chunks":1}`, 400},
		{"file.allocate", `{"Size":16,"chunks":1}`, 400},
		{"chunk.put", `{"id":"` + id + `","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`, 400},
		{"chunk.put", `{"idx":0,"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`, 400},
		{"chunk.put", `{"ciphertext":"` + strings.Repeat("A", 42) + `B"}`, 400},
		{"share.put", `{"user_id":"00000000-0000-4000-8000-000000000002","envelope":{}}`, 400},
		{"file.allocate", `{}` + strings.Repeat(" ", documentsJSONLimit), 413},
		{"key.reset", `{"user_id":"00000000-0000-0000-0000-000000000000","key_id":"` + id + `"}`, 400},
		{"key.reset", `{"user_id":"00000000-0000-4000-8000-000000000002","key_id":"bad"}`, 400},
		{"unknown", `{}`, 400},
		{"file.fetch", `{}`, 400},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			command, status := parseDocumentsPayload(documentsCommand{operation: tc.operation, ID: id, Idx: 5}, []byte(tc.body))
			if status != tc.status {
				t.Fatalf("payload status %d, want %d", status, tc.status)
			}
			if status == 200 && (command.operation != tc.operation || command.ID != id || command.Idx != 5) {
				t.Fatal("payload changed the route-selected resource")
			}
		})
	}
}

func TestDocumentsOperationPaths(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const userID = "00000000-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		path, operation, method string
		body                    bool
	}{
		{"bootstrap", "bootstrap", "GET", false},
		{"keys/fetch", "key.fetch", "GET", false},
		{"keys/register", "key.register", "PUT", true},
		{"key/" + userID + "/lookup", "key.lookup", "GET", false},
		{"keys/reset", "key.reset", "POST", true},
		{"files", "file.list", "GET", false},
		{"files/allocate", "file.allocate", "POST", true},
		{"file/" + id + "/manifest", "file.manifest", "PUT", true},
		{"file/" + id + "/commit", "file.commit", "POST", false},
		{"file/" + id + "/fetch", "file.fetch", "GET", false},
		{"file/" + id + "/delete", "file.delete", "DELETE", false},
		{"file/" + id + "/chunk/3/put", "chunk.put", "PUT", true},
		{"file/" + id + "/chunk/3/fetch", "chunk.fetch", "GET", false},
		{"file/" + id + "/share/list", "share.list", "GET", false},
		{"file/" + id + "/share/" + userID + "/put", "share.put", "PUT", true},
		{"file/" + id + "/share/" + userID + "/delete", "share.delete", "DELETE", false},
	} {
		for _, base := range []string{"", "/", "/auth", "/team/portal"} {
			path := strings.TrimSuffix(base, "/") + "/api/documents/" + tc.path
			command, status := documentsRoute(path, "", base)
			if status != 200 || command.operation != tc.operation || documentsOperationMethod(command.operation) != tc.method || documentsHasBody(command.operation) != tc.body {
				t.Fatalf("incorrect routing for %s", path)
			}
			if strings.Contains(tc.path, id) && command.ID != id || strings.Contains(tc.path, userID) && command.UserID != userID || strings.Contains(tc.path, "/chunk/") && command.Idx != 3 {
				t.Fatal("route lost its resource parameters")
			}
			for _, bad := range []string{path + "/", path + "/extra", path + "/../bootstrap", path + "/api/logout", "/other" + path} {
				if _, status := documentsRoute(bad, "", base); status != 404 {
					t.Errorf("noncanonical route %q accepted", bad)
				}
			}
			if _, status := documentsRoute(path, path, base); status != 404 {
				t.Fatal("encoded route selected an operation")
			}
		}
	}
	for _, suffix := range []string{"", "/", "/unknown", "/key.fetch", "/keys//fetch", "/Keys/fetch", "/keys/get", "/file/get", "/chunk/get", "/file/delete", "/chunk/fetch", "/share/put", "/file/list", "/file/allocate", "/key/fetch", "/key/register", "/key/reset", "/files/list", "/files/fetch", "/files/reset", "/keys", "/keys/allocate"} {
		if _, status := documentsRoute("/auth/api/documents"+suffix, "", "/auth"); status != 404 {
			t.Errorf("unknown route %q accepted", suffix)
		}
	}
	for _, suffix := range []string{"file/bad/delete", "file//fetch", "key/bad/lookup", "file/" + id + "/share/bad/delete", "file/" + id + "/chunk/-1/fetch", "file/" + id + "/chunk/01/fetch", "file/" + id + "/chunk/+1/fetch", "file/" + id + "/chunk/4096/fetch", "file/" + id + "/chunk/1.0/fetch", "file/" + id + "/chunk/9999999999999999999999999/fetch"} {
		if _, status := documentsRoute("/auth/api/documents/"+suffix, "", "/auth"); status != 400 {
			t.Errorf("invalid resource parameters accepted in %s", suffix)
		}
	}
	if documentsOperationMethod("unknown") != "" {
		t.Fatal("unknown operation has a method")
	}
}

func TestDocumentsListQuery(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		operation, query string
		force            bool
		status           int
	}{
		{"file.list", "", false, 200}, {"bootstrap", "", false, 200},
		{"file.list", "after=" + id, false, 200},
		{"file.list", "", true, 400}, {"file.list", "after=", false, 400},
		{"file.list", "after=bad", false, 400}, {"file.list", "After=" + id, false, 400},
		{"file.list", "%61fter=" + id, false, 400},
		{"file.list", "after=" + id + "&after=" + id, false, 400},
		{"file.list", "after=" + id + "&", false, 400},
		{"file.list", "after=" + id + ";other=1", false, 400},
		{"file.fetch", "after=" + id, false, 400},
		{"key.reset", "user_id=other", false, 400},
	} {
		command := documentsCommand{operation: tc.operation}
		if status := parseDocumentsQuery(&command, tc.query, tc.force); status != tc.status {
			t.Fatalf("query status %d, want %d", status, tc.status)
		}
		if tc.status == 200 && tc.query != "" && command.After != id {
			t.Fatal("list cursor lost")
		}
	}
}
