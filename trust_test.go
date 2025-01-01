// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychainjwt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/keychainjwt/keychaintest"
)

type jwtTest struct {
	jwt    string
	header string
	alg    string
	key    any
	err    error
}

func TestEndToEnd(t *testing.T) {
	errUnknown := errors.New("unknown")
	require.Error(t, errUnknown)

	a, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root"))
	require.NoError(t, err)
	require.NotEmpty(t, &a)

	b, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900)<-ica(1.2.100)<-root"))
	require.NoError(t, err)
	require.NotEmpty(t, &b)

	var neverTrusted string
	{
		c, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root"))
		require.NoError(t, err)
		require.NotEmpty(t, &c)

		neverTrusted, err = CreateSignedJWT(c)
		require.NoError(t, err)
		require.NotEmpty(t, neverTrusted)
	}

	aJWT, err := CreateSignedJWT(a)
	require.NoError(t, err)
	require.NotEmpty(t, aJWT)

	bJWT, err := CreateSignedJWT(b)
	require.NoError(t, err)
	require.NotEmpty(t, bJWT)

	common := []jwtTest{
		{
			jwt: neverTrusted,
			err: errUnknown,
		}, {
			header: "{}",
			err:    ErrMissingHeader,
		}, {
			header: `{"alg":"none"}`,
			err:    ErrDisallowedAlg,
		}, {
			header: `{"alg":"HS256"}`,
			err:    ErrDisallowedAlg,
		}, {
			header: `{"alg":"RS256"}`,
			err:    ErrMissingHeader,
		}, {
			header: `{"alg":"RS256", "x5c":[]}`,
			err:    ErrInvalidCert,
		}, {
			header: `{"alg":"RS256", "x5c":["invalid base64"]}`,
			err:    ErrDecodingCert,
		}, {
			header: `{"alg":"RS256", "x5c":["e30="]}`,
			err:    ErrParsingCert,
		}, {
			jwt: "not a JWT",
			err: errUnknown,
		},
	}

	tests := []struct {
		desc   string
		opts   []Option
		newErr error
		checks []jwtTest
	}{
		{
			desc:   "no options",
			newErr: nil,
		}, {
			desc: "trust without policies check",
			opts: []Option{
				TrustedRoots(a.Root().Public),
			},
			newErr: nil,
			checks: []jwtTest{
				{
					jwt: aJWT,
					alg: "ES256",
					key: a.Leaf().Public.PublicKey,
				}, {
					jwt: bJWT,
					err: errUnknown,
				},
			},
		}, {
			desc: "trust with policies check",
			opts: []Option{
				TrustedRoots(a.Root().Public),
				TrustedRoots(b.Root().Public),
				RequirePolicies("1.2.100", "1.2.900"),
			},
			newErr: nil,
			checks: []jwtTest{
				{
					jwt: aJWT,
				}, {
					jwt: bJWT,
				},
			},
		}, {
			desc: "trust with policies check, missing policy",
			opts: []Option{
				TrustedRoots(a.Root().Public),
				TrustedRoots(b.Root().Public),
				RequirePolicies("1.2.100", "1.2.900", "1.2.901"),
			},
			newErr: nil,
			checks: []jwtTest{
				{
					jwt: aJWT,
				}, {
					jwt: bJWT,
					err: ErrMissingPolicy,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			obj, err := New(tt.opts...)

			if tt.newErr != nil {
				assert.Nil(obj)
				require.Error(err)
				if !errors.Is(tt.newErr, errUnknown) {
					require.ErrorIs(err, tt.newErr)
				}
				return
			}

			require.NotNil(obj)
			require.NoError(err)

			checks := append(common, tt.checks...)
			for _, check := range checks {

				jwt := check.jwt
				if jwt == "" {
					h := base64.URLEncoding.EncodeToString([]byte(check.header))
					b := base64.URLEncoding.EncodeToString([]byte("{}"))
					s := ""

					h = strings.ReplaceAll(h, "=", "")
					b = strings.ReplaceAll(b, "=", "")
					jwt = strings.Join([]string{h, b, s}, ".")
				}
				alg, k, err := obj.GetKey([]byte(jwt))

				if check.err != nil {
					assert.Empty(alg)
					assert.Empty(k)
					require.Error(err)
					if !errors.Is(check.err, errUnknown) {
						require.ErrorIs(err, check.err)
					}
					continue
				}

				assert.NotEmpty(alg)
				assert.NotNil(k)
				require.NoError(err)

				if check.alg != "" {
					assert.Equal(check.alg, alg)
				}

				if check.key != nil {
					assert.Equal(check.key, k)
				}
			}
		})
	}
}
