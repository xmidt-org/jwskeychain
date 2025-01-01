// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package keychainjwt provides functionality for handling JSON Web Signatures (JWS)
// and JSON Web Tokens (JWT) with support for certificate-based trust chains. It allows
// for the verification of signatures using trusted root and intermediate certificates
// specified in the x5c header of the JWS/JWT. The package also supports customizable
// trust policies and options for flexible configuration.

package keychainjwt

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Trust is a struct that holds the trusted roots, intermediates, and policies
// for verifying a JWT or JWS signature based on the x5c header.
type Trust struct {
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	policies      []string
	now           func() time.Time
}

// New creates a new Trust object with the provided options.  If no options are
// provided, the Trust object is created with no trusted roots, intermediates,
// or required policies.  The current time function is set to time.Now by default.
// Unless the system CA store is passed in as an option, it is not used since
// that would default to trusting more than expected.
func New(opts ...Option) (*Trust, error) {
	var r Trust

	defaults := []Option{
		WithTimeFunc(nil),
	}

	opts = append(defaults, opts...)

	for _, opt := range opts {
		if opt != nil {
			opt.apply(&r)
		}
	}

	return &r, nil
}

// GetKey returns the public key from the x5c header of a JWS/JWT signature if
// the signature is valid and the certificate chain is trusted.  The public key
// is returned as an interface{} to allow for different key types.  If the
// provided text is not a valid JWS/JWT, the x5c header is missing, or the
// certificate chain is not trusted, an error is returned.  The algorithm
// string provided in the header is also returned.
func (t Trust) GetKey(text []byte) (alg string, key any, err error) {
	untrusted, err := jws.Parse(text)
	if err != nil {
		return "", nil, errors.Join(err, ErrParsingJWT)
	}

	sigs := untrusted.Signatures()
	if len(sigs) != 1 {
		return "", nil, errors.Join(ErrUnexpectedSigner, ErrParsingJWT)
	}

	signer := sigs[0]
	headers := signer.ProtectedHeaders()

	// Get the algorithm
	a := headers.Algorithm()
	if a == "" {
		err := fmt.Errorf("%w %s", ErrMissingHeader, jws.AlgorithmKey)
		return "", nil, errors.Join(err, ErrParsingJWT)
	}

	// Prevent an attacker from using a symmetric cipher or none with a valid
	// trust chain, as either will bypass the trust chain.
	if a == jwa.NoSignature || a.IsSymmetric() {
		err := fmt.Errorf("%w %s", ErrDisallowedAlg, a.String())
		return "", nil, errors.Join(err, ErrParsingJWT)
	}

	// Verify the certificate chain against the trusted roots
	chains, err := t.withPolicies(t.verify(chainToCerts(headers.X509CertChain())))
	if err != nil {
		return "", nil, err
	}

	// We only care about the leaf node which is always the first cert in any
	// returned chain, so always choose the first.
	return a.String(), chains[0][0].PublicKey, nil
}

// verify takes the output from the x5cTox509 function and verifies it.  If no
// cert chain or an error is passed in, an error results.
func (t Trust) verify(chain []*x509.Certificate, err error) ([][]*x509.Certificate, error) {
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, ErrInvalidCert
	}

	roots := x509.NewCertPool()
	for _, root := range t.roots {
		roots.AddCert(root)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range append(t.intermediates, chain[1:]...) {
		intermediates.AddCert(cert)
	}

	rv, err := chain[0].Verify(
		x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   t.now(),
		})

	if err != nil || rv == nil {
		return nil, errors.Join(err, ErrInvalidCert)
	}
	return rv, nil
}

// withPolicies filters out all chains that don't have fully matching policies.
// If no chains are left, an error is returned.  A chain can have more policies
// than are required, but not fewer.
func (t Trust) withPolicies(chains [][]*x509.Certificate, err error) ([][]*x509.Certificate, error) {
	if err != nil {
		return nil, err
	}

	rv := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		if t.hasPolicies(chain) {
			rv = append(rv, chain)
		}
	}

	if len(rv) == 0 {
		return nil, ErrMissingPolicy
	}
	return rv, nil
}

// hasPolicies checks a chain to ensure that all required policies are found in
// the chain.
func (t Trust) hasPolicies(chain []*x509.Certificate) bool {
	// Check that at least one certificate in the chain contains each of the
	// required policies.
	required := make(map[string]bool, len(t.policies))
	for _, policy := range t.policies {
		required[policy] = false
	}

	for _, cert := range chain {
		for _, policy := range cert.PolicyIdentifiers {
			if _, ok := required[policy.String()]; ok {
				required[policy.String()] = true
			}
		}
	}

	for _, matched := range required {
		if !matched {
			return false
		}
	}

	return true
}

// chainToCerts converts the cert.Chain into an array of x509 certificates for
// processing or returns an error.  A nil chain is considered an error.
func chainToCerts(chain *cert.Chain) ([]*x509.Certificate, error) {
	if chain == nil {
		return nil, errors.Join(ErrMissingHeader, ErrParsingJWT)
	}

	// Decode the certificate chain
	var rv []*x509.Certificate

	for i := 0; i < chain.Len(); i++ {
		certStr, _ := chain.Get(i)

		certData, err := base64.URLEncoding.DecodeString(string(certStr))
		if err != nil {
			return nil, errors.Join(ErrParsingJWT, ErrDecodingCert, err)
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, errors.Join(ErrParsingJWT, ErrParsingCert, err)
		}

		rv = append(rv, cert)
	}

	return rv, nil
}
