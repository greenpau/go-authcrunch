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

package errors

// JWKS Errors
const (
	ErrJwksKeyIDEmpty          StandardError = "jwks key id is empty"
	ErrJwksKeyAlgoUnsupported  StandardError = "jwks unsupported key algorithm %s for %s"
	ErrJwksKeyTypeEmpty        StandardError = "jwks key type is empty for %s"
	ErrJwksKeyTypeUnsupported  StandardError = "jwks unsupported key type %s for %s"
	ErrJwksKeyUsageEmpty       StandardError = "jwks key usage is empty for %s"
	ErrJwksKeyUsageUnsupported StandardError = "jwks unsupported key usage %s for %s"
	ErrJwksKeyExponentEmpty    StandardError = "jwks key exponent is empty for %s"
	ErrJwksKeyModulusEmpty     StandardError = "jwks key modulus is empty for %s"
	ErrJwksKeyDecodeModulus    StandardError = "jwks failed to decode key %q modulus %q: %v"
	ErrJwksKeyDecodeExponent   StandardError = "jwks failed to decode key %q exponent: %v"
	ErrJwksKeyConvExponent     StandardError = "jwks failed to decode key %q exponent: %v"

	ErrJwksKeyCurveEmpty         StandardError = "jwks key curve is empty for %s"
	ErrJwksKeyCurveUnsupported   StandardError = "jwks unsupported key curve %s for %s"
	ErrJwksKeyCurveCoordNotFound StandardError = "jwks key %q curve has no x/y coordinates"
	ErrJwksKeyCoordLength        StandardError = "jwks key %q curve %s coordinate is %d bytes in length, exp: %d bytes"
	ErrJwksKeyDecodeCoord        StandardError = "jwks failed to decode key %q curve %s coordinate: %v"

	ErrJwksKeySharedSecretEmpty  StandardError = "jwks shared secret key for %s is empty"
	ErrJwksKeyDecodeSharedSecret StandardError = "jwks failed to decode shared secret key %q: %v"

	ErrJwksKeyTypeNotImplemented StandardError = "jwks key %q type %q processing not implemented: %v"
)
