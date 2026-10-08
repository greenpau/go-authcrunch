// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
)

// Compare schema boundaries to the selected dependency's actual constructors.
// Registration and account lookup intentionally have different rules.
func TestRepositoryLocalAccountValidators(t *testing.T) {
	compiler, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	email, err := SchemaAt(compiler, "/components/schemas/LocalAccountEmail")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"alice@example.test", "A..B@EXAMPLE.test", "a@b", "a@xn--bcher-kva.test",
		" alice@example.test", "alice@example.test\n", "alice@-example.test",
		"alice@example-.test", "alice@bücher.test", "álîce@example.test",
		"alice@" + strings.Repeat("a", 63), "alice@" + strings.Repeat("a", 64),
		strings.Repeat("a", 260) + "@example.test", "Alice <alice@example.test>",
	} {
		_, runtimeErr := identity.NewEmailAddress(value)
		if (email.Validate(value) == nil) != (runtimeErr == nil) {
			t.Errorf("email schema disagrees with selected validator for %q", value)
		}
	}
	role, err := SchemaAt(compiler, "/components/schemas/LocalRoleInput")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := SchemaAt(compiler, "/components/schemas/IdentityRole")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", " \t\r\n", "\u0085\u00a0\u2003\u202f\u3000", "\ufeff", "\x00", " team/reader ", "/reader", "team/", "/", "team/a/b", "Reader"} {
		runtime, runtimeErr := identity.NewRole(value)
		if (role.Validate(value) == nil) != (runtimeErr == nil) {
			t.Errorf("role schema disagrees with selected validator for %q", value)
		}
		if runtimeErr == nil {
			encoded, err := jsonValue(runtime)
			if err != nil || stored.Validate(encoded) != nil {
				t.Errorf("stored role serializer disagrees with schema for %q", value)
			}
		}
	}
	nameSchema, err := SchemaAt(compiler, "/components/schemas/IdentityName")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, display string }{
		{" Doe, Jane ", "Doe, Jane"}, {"Jane Doe", "Doe, Jane"},
		{"Jane Middle Doe", "Jane Middle Doe"}, {"Jane  Doe", "Jane  Doe"},
	} {
		name, err := identity.ParseName(tc.input)
		if err != nil || name.GetFullName() != tc.display {
			t.Fatal("selected name parser changed")
		}
		encoded, err := jsonValue(name)
		if err != nil || nameSchema.Validate(encoded) != nil {
			t.Fatal("stored name disagrees with schema")
		}
	}
}
