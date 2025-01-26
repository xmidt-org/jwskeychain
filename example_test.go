// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/jwskeychain"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

func CreateSignedJWT(keychain keychaintest.Chain, payload []byte) ([]byte, error) {
	// This block shows how you can use the Signer() function.
	key, err := jwskeychain.Signer(jwa.ES256,
		keychain.Leaf().Private,
		keychain.Included())
	if err != nil {
		return nil, err
	}

	// Sign the inner payload with the private key.
	signed, err := jws.Sign(payload, key)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func Example() {
	trustedChain, _ := keychaintest.New(keychaintest.Desc("leaf<-ica<-root"))
	provider, _ := jwskeychain.New(jwskeychain.TrustedRoots(trustedChain.Root().Public))
	trustedJWS, _ := CreateSignedJWT(trustedChain, []byte("hello, world, I'm trusted"))

	untrustedChain, _ := keychaintest.New(keychaintest.Desc("leaf<-ica<-root"))
	untrustedJWS, _ := CreateSignedJWT(untrustedChain, []byte("hello, world, I'm untrusted"))

	payload, err := jws.Verify(trustedJWS, jws.WithKeyProvider(provider))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(payload))

	_, err = jws.Verify(untrustedJWS, jws.WithKeyProvider(provider))
	if err == nil {
		panic("expected an error")
	}

	// Output:
	// hello, world, I'm trusted
}
