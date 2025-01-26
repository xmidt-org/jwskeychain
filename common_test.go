// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

func createSignedJWT(keychain keychaintest.Chain) ([]byte, error) {
	key, err := Signer(jwa.ES256,
		keychain.Leaf().Private,
		keychain.Included())
	if err != nil {
		return nil, err
	}

	// Sign the inner payload with the private key.
	signed, err := jws.Sign([]byte("{}"), key)
	if err != nil {
		return nil, err
	}

	return signed, nil
}
