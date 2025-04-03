// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

func TestSigner(t *testing.T) {
	unknownErr := errors.New("unknown error")
	chain, err := keychaintest.New(keychaintest.Desc("leaf<-ica<-root"))
	require.NoError(t, err)
	require.NotNil(t, chain)

	tests := []struct {
		desc    string
		alg     jwa.SignatureAlgorithm
		private any
		certs   []keychaintest.Node
		err     error
	}{
		{
			desc: "empty chain",
			alg:  jwa.ES256(),
			err:  ErrInvalidx509Chain,
		}, {
			desc:  "root cert",
			alg:   jwa.ES256(),
			certs: chain,
		}, {
			desc:  "invalid symmetric alg",
			alg:   jwa.HS256(),
			certs: chain,
			err:   ErrInvalidAlg,
		}, {
			desc:  "invalid symmetric alg",
			alg:   jwa.NoSignature(),
			certs: chain,
			err:   ErrInvalidAlg,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {

			certs := make([]*x509.Certificate, len(tc.certs))
			for i := range tc.certs {
				certs[i] = tc.certs[i].Public
			}

			got, err := Signer(tc.alg, tc.private, certs)

			if tc.err != nil {
				require.Error(t, err)
				require.Nil(t, got)
				if !errors.Is(tc.err, unknownErr) {
					require.ErrorIs(t, err, tc.err)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}
