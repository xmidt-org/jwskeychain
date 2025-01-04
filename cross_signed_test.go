// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

func TestCrossSigning(t *testing.T) {
	// A is valid from 2020-01-01 to 2022-01-01
	aStart := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	aEnd := aStart.AddDate(2, 0, 0)

	// B is valid from 2021-01-01 to 2023-01-01
	bStart := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	bEnd := bStart.AddDate(2, 0, 0)

	aEarly := aStart.AddDate(-1, 0, 0)
	aValid := aStart.AddDate(0, 1, 0)
	aLate := aEnd.AddDate(2, 1, 0)

	aAndBValid := aStart.AddDate(1, 1, 0)

	bEarly := bStart.AddDate(-1, 0, 0)
	bValid := bStart.AddDate(1, 1, 0)
	bLate := bEnd.AddDate(2, 1, 0)

	a, err := keychaintest.New(
		keychaintest.Desc("leaf<-ica(1.2.100)<-root"),
		keychaintest.NotBefore(aStart),
		keychaintest.NotAfter(aEnd),
	)
	require.NoError(t, err)
	require.NotEmpty(t, &a)

	b, err := keychaintest.New(
		keychaintest.Desc("leaf<-ica(1.2.200)<-root"),
		keychaintest.NotBefore(bStart),
		keychaintest.NotAfter(bEnd),
	)
	require.NoError(t, err)
	require.NotEmpty(t, &b)

	// C is valid from 2021-01-01 to 2023-01-01
	c, err := keychaintest.New(
		keychaintest.Desc("leaf<-ica(1.2.100,1.2.200)<-root"),
		keychaintest.NotBefore(aStart),
		keychaintest.NotAfter(bEnd),
	)
	require.NoError(t, err)
	require.NotEmpty(t, &c)

	// cross sign c ica with a root
	var axc keychaintest.Chain
	{
		tmp, err := crossSign(c.Intermediates()[0], a.Root())
		require.NoError(t, err)
		require.NotEmpty(t, &tmp)
		axc = keychaintest.Chain{c.Leaf(), tmp, a.Root()}
	}
	require.NotEmpty(t, &axc)

	// cross sign b ica with a root
	var bxc keychaintest.Chain
	{
		tmp, err := crossSign(c.Intermediates()[0], b.Root())
		require.NoError(t, err)
		require.NotEmpty(t, &tmp)
		bxc = keychaintest.Chain{c.Leaf(), tmp, b.Root()}
	}
	require.NotEmpty(t, &bxc)

	aJwt, err := CreateSignedJWT(a)
	require.NoError(t, err)
	require.NotEmpty(t, aJwt)

	bJwt, err := CreateSignedJWT(b)
	require.NoError(t, err)
	require.NotEmpty(t, bJwt)

	cJwt, err := CreateSignedJWT(c)
	require.NoError(t, err)
	require.NotEmpty(t, cJwt)

	axcJwt, err := CreateSignedJWT(axc)
	require.NoError(t, err)
	require.NotEmpty(t, axcJwt)

	bxcJwt, err := CreateSignedJWT(bxc)
	require.NoError(t, err)
	require.NotEmpty(t, bxcJwt)

	// -- test ----------------------------------------------------------------
	errUnknown := fmt.Errorf("unknown")
	require.Error(t, errUnknown)

	tests := []struct {
		desc     string
		jwt      []byte
		policies []string
		now      time.Time
		err      error
		key      any
	}{
		// a signed certificates
		{
			desc: "aJwt is too early",
			jwt:  aJwt,
			now:  aEarly,
			err:  errUnknown,
		}, {
			desc: "aJwt is valid",
			jwt:  aJwt,
			now:  aValid,
			key:  a[0].Public.PublicKey,
		}, {
			desc: "aJwt is too late",
			jwt:  aJwt,
			now:  aLate,
			err:  errUnknown,
		},

		// b signed certificates
		{
			desc: "bJwt is too early",
			jwt:  bJwt,
			now:  bEarly,
			err:  errUnknown,
		}, {
			desc: "bJwt is valid during overlap with a",
			jwt:  bJwt,
			now:  aAndBValid,
			key:  b[0].Public.PublicKey,
		}, {
			desc: "bJwt is valid after a expires",
			jwt:  bJwt,
			now:  bValid,
			key:  b[0].Public.PublicKey,
		}, {
			desc: "bJwt is too late",
			jwt:  bJwt,
			now:  bLate,
			err:  errUnknown,
		},

		// c signed certificates are always invalid
		{
			desc: "cJwt is invalid",
			jwt:  cJwt,
			now:  aAndBValid,
			err:  errUnknown,
		},

		// a cross signed certificates
		{
			desc: "axcJwt is invalid while a is too early",
			jwt:  axcJwt,
			now:  aEarly,
			err:  errUnknown,
		}, {
			desc: "axcJwt is valid while a is valid",
			jwt:  axcJwt,
			now:  aValid,
			key:  axc[0].Public.PublicKey,
		}, {
			desc: "axcJwt is valid while a and b are valid",
			jwt:  axcJwt,
			now:  aAndBValid,
			key:  axc[0].Public.PublicKey,
		}, {
			desc: "axcJwt is invalid after a expires",
			jwt:  axcJwt,
			now:  aLate,
			err:  errUnknown,
		},

		// b cross signed certificates
		{
			desc: "bxcJwt is invalid while b is too early",
			jwt:  bxcJwt,
			now:  bEarly,
			err:  errUnknown,
		}, {
			desc: "bxcJwt is valid during overlap",
			jwt:  bxcJwt,
			now:  aAndBValid,
			key:  bxc[0].Public.PublicKey,
		}, {
			desc: "bxcJwt is valid during b validity",
			jwt:  bxcJwt,
			now:  bValid,
			key:  bxc[0].Public.PublicKey,
		}, {
			desc: "bxcJwt is too late",
			jwt:  bxcJwt,
			now:  bLate,
			err:  errUnknown,
		},

		{
			desc:     "axcJwt is valid with a policy",
			jwt:      axcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.100"},
			key:      axc[0].Public.PublicKey,
		}, {
			desc:     "axcJwt is invalid with a missing policy",
			jwt:      axcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.101"},
			err:      errUnknown,
		}, {
			desc:     "bxcJwt is valid with a policy",
			jwt:      bxcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.200"},
			key:      bxc[0].Public.PublicKey,
		}, {
			desc:     "bxcJwt is invalid with a missing policy",
			jwt:      bxcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.201"},
			err:      errUnknown,
		},

		{
			desc:     "axcJwt is valid with both policies",
			jwt:      axcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.100", "1.2.200"},
			key:      axc[0].Public.PublicKey,
		}, {
			desc:     "bxcJwt is valid with both policies",
			jwt:      bxcJwt,
			now:      aAndBValid,
			policies: []string{"1.2.100", "1.2.200"},
			key:      bxc[0].Public.PublicKey,
		}, {
			desc:     "aJwt is invalid with a missing policy",
			jwt:      aJwt,
			now:      aAndBValid,
			policies: []string{"1.2.100", "1.2.200"},
			err:      errUnknown,
		}, {
			desc:     "bJwt is invalid with a missing policy",
			jwt:      bJwt,
			now:      aAndBValid,
			policies: []string{"1.2.100", "1.2.200"},
			err:      errUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			trust, err := New(
				TrustedRoots(a.Root().Public, b.Root().Public),
				RequirePolicies(test.policies...),
				WithTimeFunc(func() time.Time {
					return test.now
				}),
			)
			require.NoError(t, err)
			require.NotEmpty(t, trust)

			payload, err := jws.Verify(test.jwt, jws.WithKeyProvider(trust))

			if test.err != nil {
				assert.Nil(t, payload)
				require.Error(t, err)
				if !errors.Is(test.err, errUnknown) {
					require.ErrorIs(t, err, test.err)
				}
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, payload)
		})
	}
}

func crossSign(ica keychaintest.Node, root keychaintest.Node) (keychaintest.Node, error) {
	// Create a template for the cross-signed certificate
	crossSignedTemplate := *ica.Public
	crossSignedTemplate.Issuer = root.Public.Subject
	crossSignedTemplate.AuthorityKeyId = root.Public.SubjectKeyId

	// Create the cross-signed certificate
	crossSignedCertDER, err := x509.CreateCertificate(rand.Reader, &crossSignedTemplate, root.Public, &ica.Private.PublicKey, root.Private)
	if err != nil {
		return keychaintest.Node{}, fmt.Errorf("failed to create cross-signed certificate: %v", err)
	}

	// Parse the cross-signed certificate
	crossSignedCert, err := x509.ParseCertificate(crossSignedCertDER)
	if err != nil {
		return keychaintest.Node{}, fmt.Errorf("failed to parse cross-signed certificate: %v", err)
	}

	// Return the new Node with the cross-signed certificate and the original private key
	return keychaintest.Node{
		Public:  crossSignedCert,
		Private: ica.Private,
	}, nil
}
