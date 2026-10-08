// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestRepositoryCredentialVerifiers(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	bcryptSchema, err := SchemaAt(c, "/components/schemas/BcryptHash")
	if err != nil {
		t.Fatal(err)
	}
	argonSchema, err := SchemaAt(c, "/components/schemas/Argon2Hash")
	if err != nil {
		t.Fatal(err)
	}
	passwordSchema, err := SchemaAt(c, "/components/schemas/IdentityPasswordRecord")
	if err != nil {
		t.Fatal(err)
	}
	apiSchema, err := SchemaAt(c, "/components/schemas/ProfileAPIKeyRecord")
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("k", 72)
	password, err := identity.NewPassword(secret)
	if err != nil {
		t.Fatal("cannot generate synthetic bcrypt verifier")
	}
	for _, prefix := range []string{"$2$", "$2a$", "$2b$", "$2x$", "$2y$"} {
		hash := prefix + password.Hash[4:]
		imported, err := identity.ParseHashedPassword("bcrypt:10:" + hash)
		if err != nil || bcryptSchema.Validate(hash) != nil {
			t.Fatal("supported bcrypt import and schema disagree")
		}
		value, err := jsonValue(imported)
		if err != nil || passwordSchema.Validate(value) != nil {
			t.Fatal("bcrypt password record rejected")
		}
	}
	for _, hash := range []string{
		strings.Replace(password.Hash, "$2a$", "$2z$", 1),
		password.Hash + "=", password.Hash[:59] + "B",
		strings.Replace(password.Hash, "$10$", "$03$", 1),
		password.Hash[:28] + "B" + password.Hash[29:],
	} {
		_, err := identity.ParseHashedPassword("bcrypt:10:" + hash)
		if err == nil || bcryptSchema.Validate(hash) == nil {
			t.Fatal("invalid bcrypt import accepted")
		}
	}
	key, err := identity.NewAPIKey(&requests.Request{Key: requests.Key{Usage: "api", Prefix: secret[:24], Payload: password.Hash, Comment: "Synthetic"}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonValue(key)
	if err != nil || apiSchema.Validate(value) != nil {
		t.Fatal("API-key serializer and schema disagree")
	}
	if !key.Match(secret) || !key.Match(secret+"suffix") || key.Match(" "+secret) {
		t.Fatal("API-key diagnostic bcrypt byte boundary changed")
	}
	key.Expired = true
	if !key.Match(secret) {
		t.Fatal("direct diagnostic unexpectedly enforced lifecycle flags")
	}
	owner := &identity.User{APIKeys: []*identity.APIKey{key}}
	if owner.LookupAPIKey(&requests.Request{Key: requests.Key{Prefix: secret[:24], Payload: secret}}) == nil {
		t.Fatal("authentication accepted an expired key")
	}
	for _, field := range []string{"id", "prefix", "payload"} {
		fields, _ := jsonValue(key)
		fields.(map[string]any)[field] = "invalid"
		if apiSchema.Validate(fields) == nil {
			t.Fatalf("invalid API-key %s accepted", field)
		}
	}
	argon, err := identity.NewPasswordWithConfig("synthetic-password", "auth", &identity.PasswordHashConfig{Algorithm: "argon2", Memory: 256, Iterations: 2, Parallelism: 1})
	if err != nil {
		t.Fatal("cannot generate synthetic Argon2 verifier")
	}
	if argon.Algorithm != "argon2" || argon.Cost != 0 || !argon.Match("synthetic-password") {
		t.Fatal("Argon2 record semantics changed")
	}
	value, _ = jsonValue(argon)
	if passwordSchema.Validate(value) != nil || argonSchema.Validate(argon.Hash) != nil {
		t.Fatal("Argon2 serializer and schema disagree")
	}
	for _, hash := range []string{
		strings.Replace(argon.Hash, "v=19", "v=16", 1),
		strings.Replace(argon.Hash, "m=256,t=2,p=1", "t=2,m=256,p=1", 1),
		strings.Replace(argon.Hash, "m=256", "m=0256", 1),
		strings.Replace(argon.Hash, "t=2", "t=11", 1),
		strings.Replace(argon.Hash, "p=1", "p=17", 1),
		argon.Hash + "=", argon.Hash[:len(argon.Hash)-1] + "B",
	} {
		_, err := identity.ParseHashedPassword("argon2:" + hash)
		if err == nil || argonSchema.Validate(hash) == nil {
			t.Fatal("invalid Argon2 syntax accepted")
		}
	}
	// Cross-parameter work bounds are documented separately from PHC syntax.
	for _, params := range []string{"m=7,t=2,p=1", "m=8,t=2,p=2", "m=262145,t=2,p=1", "m=262144,t=5,p=1"} {
		hash := strings.Replace(argon.Hash, "m=256,t=2,p=1", params, 1)
		if _, err := identity.ParseHashedPassword("argon2:" + hash); err == nil {
			t.Fatal("unsafe Argon2 work profile accepted")
		}
	}
	fields := value.(map[string]any)
	fields["cost"] = 10
	if passwordSchema.Validate(fields) == nil {
		t.Fatal("bcrypt cost accepted for Argon2 record")
	}
	delete(fields, "cost")
	fields["algorithm"] = "bcrypt"
	if passwordSchema.Validate(fields) == nil {
		t.Fatal("mismatched algorithm/hash accepted")
	}
}
