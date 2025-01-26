// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

type jwtTest struct {
	jwt    []byte
	header string
	alg    jwa.SignatureAlgorithm
	key    any
	err    error
}

func TestEndToEnd(t *testing.T) {
	ignored := errors.New("ignored")
	errSpecific := errors.New("specific")
	errUnknown := errors.New("unknown")
	require.Error(t, errUnknown)

	a, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root"))
	require.NoError(t, err)
	require.NotEmpty(t, &a)

	b, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900)<-ica(1.2.100)<-root"))
	require.NoError(t, err)
	require.NotEmpty(t, &b)

	var neverTrusted []byte
	{
		c, err := keychaintest.New(keychaintest.Desc("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root"))
		require.NoError(t, err)
		require.NotEmpty(t, &c)

		neverTrusted, err = createSignedJWT(c)
		require.NoError(t, err)
		require.NotEmpty(t, neverTrusted)
	}

	aJWT, err := createSignedJWT(a)
	require.NoError(t, err)
	require.NotEmpty(t, aJWT)

	bJWT, err := createSignedJWT(b)
	require.NoError(t, err)
	require.NotEmpty(t, bJWT)

	common := []jwtTest{
		{
			jwt: neverTrusted,
			err: ignored,
		}, {
			header: "{}",
			err:    ignored,
		}, {
			header: `{"alg":"none"}`,
			err:    ignored,
		}, {
			header: `{"alg":"HS256"}`,
			err:    ignored,
		}, {
			header: `{"alg":"RS256"}`,
			err:    ignored,
		}, {
			header: `{"alg":"RS256", "x5c":[]}`,
			err:    ignored,
		}, {
			header: `{"alg":"RS256", "x5c":["invalid base64"]}`,
			err:    ErrParsingJWS,
		}, {
			header: `{"alg":"RS256", "x5c":["e30="]}`,
			err:    ErrParsingJWS,
		},
	}

	tests := []struct {
		desc      string
		opts      []Option
		newErr    error
		rootCount int
		checks    []jwtTest
	}{
		{
			desc:   "no options",
			newErr: nil,
		}, {
			desc:   "err option",
			opts:   []Option{errOption(errSpecific)},
			newErr: errSpecific,
		}, {
			desc: "trust without policies check",
			opts: []Option{
				TrustedRoots(a.Root().Public),
			},
			newErr:    nil,
			rootCount: 1,
			checks: []jwtTest{
				{
					jwt: aJWT,
					alg: jwa.ES256,
					key: a.Leaf().Public.PublicKey,
				}, {
					jwt: bJWT,
					err: ignored,
				},
			},
		}, {
			desc: "trust with policies check",
			opts: []Option{
				TrustedRoots(a.Root().Public),
				TrustedRoots(b.Root().Public),
				RequirePolicies("1.2.100", "1.2.900"),
			},
			newErr:    nil,
			rootCount: 2,
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
				RequirePolicies("1.2.100", "1.2.900"),
				RequirePolicies("1.2.901"),
			},
			newErr:    nil,
			rootCount: 2,
			checks: []jwtTest{
				{
					jwt: aJWT,
				}, {
					jwt: bJWT,
					err: ignored,
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

			roots := obj.Roots()

			if tt.rootCount == 0 {
				assert.Nil(roots)
			} else {
				require.NotNil(roots)
				assert.Len(roots, tt.rootCount)
			}

			checks := append(common, tt.checks...)
			for _, check := range checks {

				jwt := check.jwt
				if jwt == nil {
					h := base64.URLEncoding.EncodeToString([]byte(check.header))
					b := base64.URLEncoding.EncodeToString([]byte("{}"))
					s := ""

					h = strings.ReplaceAll(h, "=", "")
					b = strings.ReplaceAll(b, "=", "")
					jwt = []byte(strings.Join([]string{h, b, s}, "."))
				}

				ctx := context.Background()
				msg, err := jws.Parse(jwt)
				require.NoError(err)
				sigs := msg.Signatures()
				var ks mockKey
				for _, sig := range sigs {
					err = obj.FetchKeys(ctx, &ks, sig, msg)
				}

				if check.err != nil {
					assert.Empty(ks)

					if errors.Is(check.err, ignored) {
						assert.NoError(err)
						continue
					}

					require.Error(err)

					if !errors.Is(check.err, errUnknown) {
						require.ErrorIs(err, check.err)
					}
					continue
				}

				assert.NotEmpty(ks)
				assert.Len(ks.keys, 1)
				require.NoError(err)

				if check.alg != "" {
					assert.Equal(check.alg, ks.keys[0].alg)
				}

				if check.key != nil {
					assert.Equal(check.key, ks.keys[0].key)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	chain := []*x509.Certificate{}
	now := time.Now()
	err := VerifierFunc(
		func(c context.Context, ch []*x509.Certificate, n time.Time) error {
			assert.Equal(t, ctx, c)
			assert.Equal(t, chain, ch)
			assert.Equal(t, now, n)
			return nil
		},
	).Verify(ctx, chain, now)

	assert.NoError(t, err)
}
