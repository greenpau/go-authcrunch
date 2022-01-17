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

package identity

import (
	"github.com/greenpau/aaasf/pkg/requests"
	"testing"
)

func TestNewUser(t *testing.T) {
	user := NewUser("jsmith")
	if err := user.Valid(); err == nil {
		t.Fatalf("user has no password, but was found to be valid")
	}

	if err := user.AddPassword("jsmith123", 0); err != nil {
		t.Fatalf("error adding password: %s", err)
	}

	if err := user.Valid(); err != nil {
		t.Fatalf("updated user, but was found to be invalid: %s", err)
	}

	roleName := "superadmin"
	if err := user.AddRole(roleName); err != nil {
		t.Fatalf("error adding role: %s", err)
	}

	if exists := user.HasRoles(); !exists {
		t.Fatalf("added role, but the user has no roles")
	}

	if hasRole := user.HasRole(roleName); !hasRole {
		t.Fatalf("added %s role, but the user has no %s role", roleName, roleName)
	}

	pkr := requests.NewRequest()

	pkr.Key.Usage = "ssh"
	pkr.Key.Payload = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDnnPNq40sWtv6WsG4cICs3Cb0C9EIeKbccOTVFk4/Ptl5oEMWHaH/e5OYAfhPsr66jC3SxCynlViXvc5+r7r9Tj1M7WGSIomZQr7c2gwyPRwT+/UBEtPi63LIAubb9rkdnZEmxU3hxdnMzeBovFLuEMZpmL5sce+sZNMMBybGP9UCRZaJhyYxy0jEJI9hlg4jRK30vkzPzsO+DNIqdAv3PNkhUqJABeMiXnxCCSQcb5S65zJPkGCRXKOlloFNt3ps9auWpJQgprrcxXFlSCvxu2UcdjegrmOMhohrxMl/VyMpbDWcyHolvZSko8uzM/G0UoR9UMrJN/AyXdzDrciqBG9EUT9NGPoA5sqWT6lt0cS7tG7tbAfV5XoN7QikwsWkDyaPfqV9EbLOkxBZCE9RdQTVtfX9MX7rBYz2MTItZ9WLIMmsPWe4RS31JhYhSiJqgGq0K8mHors5dfgMtiVaLUXG7hUpLRZ2qn29SkI0xIRiYUqLP1pV65EbJhy+1+2Vm2AgvdQrWrSofj6Dsw8IiyDtKx7ahgKnUbV3d4rtuo1hCikXu8rTlfUEXgR7kSdxaSb5uzqDLlKSe27szZxUvwsyGbTgQfLukyQZB9Kvxq6J70XMRG7UikKvyR0m/Eetp4B8RX5gvNqpd+SOl+dm+cGuqWT7UROygyf28cCqLzQ== jsmith@outlook.com"
	pkr.Key.Comment = "jsmith@outlook.com"

	if err := user.AddPublicKey(pkr); err != nil {
		t.Fatalf("error adding ssh key: %s", err)
	}

	keyID := user.PublicKeys[0].ID
	// t.Logf("key id: %s", keyID)

	pkr = requests.NewRequest()
	pkr.Key.ID = keyID
	if err := user.DeletePublicKey(pkr); err != nil {
		t.Fatalf("error deleting ssh key: %s", err)
	}

	if len(user.PublicKeys) > 0 {
		t.Fatalf("expected 0 public keys")
	}

}
