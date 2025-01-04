// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain_test

import (
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/jwskeychain"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

func CreateSignedJWT(keychain keychaintest.Chain, payload []byte) ([]byte, error) {
	// Build certificate chain.
	var chain cert.Chain
	for _, cert := range keychain.Included() {
		err := chain.AddString(base64.URLEncoding.EncodeToString(cert.Raw))
		if err != nil {
			return nil, err
		}
	}

	// Create headers and set x5c with certificate chain.
	headers := jws.NewHeaders()
	err := headers.Set(jws.X509CertChainKey, &chain)
	if err != nil {
		return nil, err
	}

	key := jws.WithKey(jwa.ES256, keychain.Leaf().Private, jws.WithProtectedHeaders(headers))

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
}
