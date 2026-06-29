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

package oauth

import (
	"fmt"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func (b *IdentityProvider) validateAccessToken(state string, data map[string]interface{}) (map[string]interface{}, error) {
	if data == nil {
		return nil, errors.ErrIdentityProviderOAuthClaimsParserClaimsNotFound
	}

	parsedData := make(map[string]interface{})

	tokenNames := []string{"id_token"}
	if b.config.IdentityTokenFieldName != "" && b.config.IdentityTokenFieldName != "id_token" {
		tokenNames = append(tokenNames, b.config.IdentityTokenFieldName)
	}
	if b.config.IdentityTokenFieldName != "access_token" {
		tokenNames = append(tokenNames, "access_token")
	}

	for _, tokenName := range tokenNames {
		tokenStringRaw, exists := data[tokenName]
		if !exists {
			continue
		}
		isNonIdentityAccessToken := tokenName == "access_token" && tokenName != b.config.IdentityTokenFieldName

		tokenString, ok := tokenStringRaw.(string)
		if !ok {
			return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(tokenName, fmt.Errorf("not a string"))
		}

		if isNonIdentityAccessToken {
			// Access tokens may be opaque. JWT access tokens can contribute
			// claims only after the same signature checks used below.
			if !isOAuthJWTToken(tokenString) {
				continue
			}
		}

		token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
			switch {
			case strings.HasPrefix(token.Method.Alg(), "RS"):
				if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Header["alg"])
				}
			case strings.HasPrefix(token.Method.Alg(), "ES"):
				if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Header["alg"])
				}
			case strings.HasPrefix(token.Method.Alg(), "HS"):
				return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Method.Alg())
			}

			keyID, found := token.Header["kid"].(string)
			if !found {
				// If key id is not found in the header, then try the first available key.
				for _, key := range b.keys {
					return key.GetPublic(), nil
				}
				// return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotFound.WithArgs(b.config.IdentityTokenName)
			}
			key, exists := b.keys[keyID]
			if !exists {
				if !b.disableKeyVerification {
					if err := b.fetchKeysURL(); err != nil {
						return nil, errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)
					}
				}

				key, exists = b.keys[keyID]
				if !exists {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotRegistered.WithArgs(tokenName, keyID)
				}
			}
			return key.GetPublic(), nil
		})

		if err != nil {
			if isNonIdentityAccessToken {
				continue
			}
			return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(tokenName, err)
		}

		if !token.Valid {
			if isNonIdentityAccessToken {
				continue
			}
			return nil, errors.ErrIdentityProviderOAuthInvalidToken.WithArgs(tokenName, tokenString)
		}

		claims := token.Claims.(jwtlib.MapClaims)
		if err := b.validateOAuthTokenTrustClaims(tokenName, claims); err != nil {
			if isNonIdentityAccessToken {
				continue
			}
			return nil, err
		}
		if tokenName == b.config.IdentityTokenFieldName || tokenName == "id_token" {
			if _, exists := claims["nonce"]; !exists {
				return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(tokenName, "nonce not found")
			}
			if err := b.state.validateNonce(state, claims["nonce"].(string)); err != nil {
				return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(tokenName, err)
			}

			if !b.disableEmailClaimCheck {
				if _, exists := claims["email"]; !exists {
					return nil, errors.ErrIdentityProviderOAuthEmailNotFound.WithArgs(tokenName)
				}
			}
		}

		if err := b.parseTokenClaims(tokenName, claims, data, parsedData); err != nil {
			return nil, err
		}
	}

	if len(parsedData) == 0 {
		return nil, errors.ErrIdentityProviderOAuthClaimsParserClaimsNotFound
	}

	if _, exists := parsedData["name"]; !exists {
		if _, exists := parsedData["given_name"]; exists {
			if _, exists := parsedData["family_name"]; exists {
				parsedData["name"] = fmt.Sprintf("%s %s", parsedData["given_name"].(string), parsedData["family_name"].(string))
				delete(parsedData, "given_name")
				delete(parsedData, "family_name")
			}
		}
	}

	return parsedData, nil
}

func (b *IdentityProvider) validateOAuthTokenTrustClaims(tokenName string, claims jwtlib.MapClaims) error {
	if err := b.validateOAuthTokenIssuer(tokenName, claims); err != nil {
		return err
	}
	if err := b.validateOAuthTokenAudience(tokenName, claims); err != nil {
		return err
	}
	return nil
}

func (b *IdentityProvider) validateOAuthTokenIssuer(tokenName string, claims jwtlib.MapClaims) error {
	expectedIssuer := b.expectedOAuthTokenIssuer()
	if expectedIssuer == "" {
		return nil
	}

	issuer, exists, err := getOAuthStringClaim(claims, "iss")
	if err != nil {
		return errors.ErrIdentityProviderOAuthIssuerValidationFailed.WithArgs(tokenName, err)
	}
	if !exists {
		return errors.ErrIdentityProviderOAuthIssuerValidationFailed.WithArgs(tokenName, "iss not found")
	}
	if issuer != expectedIssuer {
		return errors.ErrIdentityProviderOAuthIssuerValidationFailed.WithArgs(tokenName, fmt.Errorf("got %q, expected %q", issuer, expectedIssuer))
	}
	return nil
}

func (b *IdentityProvider) validateOAuthTokenAudience(tokenName string, claims jwtlib.MapClaims) error {
	expectedAudience := b.expectedOAuthTokenAudience(tokenName)
	if expectedAudience == "" {
		return nil
	}

	audiences, exists, err := getOAuthAudienceClaim(claims)
	if err != nil {
		return errors.ErrIdentityProviderOAuthAudienceValidationFailed.WithArgs(tokenName, err)
	}
	if !exists {
		return errors.ErrIdentityProviderOAuthAudienceValidationFailed.WithArgs(tokenName, "aud not found")
	}

	isIdentityToken := tokenName == b.config.IdentityTokenFieldName || tokenName == "id_token"
	if containsOAuthString(audiences, expectedAudience) {
		if err := b.validateOAuthTokenAuthorizedParty(tokenName, claims, len(audiences) > 1 && isIdentityToken); err != nil {
			return err
		}
		return nil
	}

	// Some providers issue JWT access tokens whose aud identifies the protected
	// resource while azp identifies the OAuth client that received the token.
	if tokenName == "access_token" && !isIdentityToken && b.config.AccessTokenAudience == "" {
		return b.validateOAuthTokenAuthorizedParty(tokenName, claims, true)
	}

	return errors.ErrIdentityProviderOAuthAudienceValidationFailed.WithArgs(tokenName, fmt.Errorf("got %v, expected %q", audiences, expectedAudience))
}

func (b *IdentityProvider) validateOAuthTokenAuthorizedParty(tokenName string, claims jwtlib.MapClaims, required bool) error {
	expectedAuthorizedParty := b.expectedOAuthAuthorizedParty()
	if expectedAuthorizedParty == "" {
		return nil
	}

	authorizedParty, exists, err := getOAuthStringClaim(claims, "azp")
	if err != nil {
		return errors.ErrIdentityProviderOAuthAzpValidationFailed.WithArgs(tokenName, err)
	}
	if !exists {
		if required {
			return errors.ErrIdentityProviderOAuthAzpValidationFailed.WithArgs(tokenName, "azp not found")
		}
		return nil
	}
	if authorizedParty != expectedAuthorizedParty {
		return errors.ErrIdentityProviderOAuthAzpValidationFailed.WithArgs(tokenName, fmt.Errorf("got %q, expected %q", authorizedParty, expectedAuthorizedParty))
	}
	return nil
}

func (b *IdentityProvider) expectedOAuthTokenIssuer() string {
	if b == nil || b.config == nil {
		return ""
	}
	if b.config.Issuer != "" {
		return b.config.Issuer
	}
	if b.metadata == nil {
		return ""
	}
	issuer, _ := b.metadata["issuer"].(string)
	return issuer
}

func (b *IdentityProvider) expectedOAuthTokenAudience(tokenName string) string {
	if b == nil || b.config == nil {
		return ""
	}
	if tokenName == "access_token" && tokenName != b.config.IdentityTokenFieldName {
		if b.config.AccessTokenAudience != "" {
			return b.config.AccessTokenAudience
		}
	}
	return b.config.ClientID
}

func (b *IdentityProvider) expectedOAuthAuthorizedParty() string {
	if b == nil || b.config == nil {
		return ""
	}
	return b.config.ClientID
}

func getOAuthStringClaim(claims jwtlib.MapClaims, key string) (string, bool, error) {
	value, exists := claims[key]
	if !exists {
		return "", false, nil
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return "", true, fmt.Errorf("%s claim is invalid", key)
	}
	return s, true, nil
}

func getOAuthAudienceClaim(claims jwtlib.MapClaims) ([]string, bool, error) {
	value, exists := claims["aud"]
	if !exists {
		return nil, false, nil
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil, true, fmt.Errorf("aud claim is empty")
		}
		return []string{v}, true, nil
	case []string:
		return validateOAuthAudienceValues(v)
	case []interface{}:
		audiences := make([]string, 0, len(v))
		for _, item := range v {
			audience, ok := item.(string)
			if !ok {
				return nil, true, fmt.Errorf("aud claim contains %T", item)
			}
			audiences = append(audiences, audience)
		}
		return validateOAuthAudienceValues(audiences)
	}
	return nil, true, fmt.Errorf("aud claim has %T type", value)
}

func validateOAuthAudienceValues(audiences []string) ([]string, bool, error) {
	if len(audiences) == 0 {
		return nil, true, fmt.Errorf("aud claim is empty")
	}
	for _, audience := range audiences {
		if audience == "" {
			return nil, true, fmt.Errorf("aud claim contains empty value")
		}
	}
	return audiences, true, nil
}

func containsOAuthString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isOAuthJWTToken(tokenString string) bool {
	if strings.Count(tokenString, ".") != 2 {
		return false
	}
	if _, _, err := new(jwtlib.Parser).ParseUnverified(tokenString, jwtlib.MapClaims{}); err != nil {
		return false
	}
	return true
}
