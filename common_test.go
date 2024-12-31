// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychainjwt

import (
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/keychainjwt/keychaintest"
)

func CreateSignedJWT(keychain keychaintest.Chain) (string, error) {
	// Build certificate chain.
	var chain cert.Chain
	for _, cert := range keychain.Included() {
		err := chain.AddString(base64.URLEncoding.EncodeToString(cert.Raw))
		if err != nil {
			return "", err
		}
	}

	// Create headers and set x5c with certificate chain.
	headers := jws.NewHeaders()
	err := headers.Set(jws.X509CertChainKey, &chain)
	if err != nil {
		return "", err
	}

	key := jws.WithKey(jwa.ES256, keychain.Leaf().Private, jws.WithProtectedHeaders(headers))

	// Sign the inner payload with the private key.
	signed, err := jws.Sign([]byte("{}"), key)
	if err != nil {
		return "", err
	}

	return string(signed), nil
}
