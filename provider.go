// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package jwskeychain provides x509 certificate chain verification for JWS/JWT
// signatures.  It allows for the verification of signatures using trusted root
// and intermediate certificates specified in the x5c header of the JWS/JWT. This
// package also supports customizable trust Verifiers and options for flexible
// configuration.
//
// This package is based on the jwx package from lestrrat-go/jwx/v2.  The
// Provider struct implements the jws.KeyProvider interface from the jwx package.
//
// See https://github.com/lestrrat-go/jwx for more information on the jwx package.
package jwskeychain

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Provider is a struct that holds the trusted roots,  and policies
// for verifying a JWT or JWS signature based on the x5c header.
type Provider struct {
	roots     []*x509.Certificate
	verifiers []Verifier
	now       func() time.Time
}

// Ensure that Provider implements the jws.KeyProvider interface.
var _ jws.KeyProvider = (*Provider)(nil)

// New creates a new Trust object with the provided options.  If no options are
// provided, the Trust object is created with no trusted roots or required
// policies.  The current time function is set to time.Now by default.
// Unless the system CA store is passed in as an option, it is not used since
// that would default to trusting more than expected.
func New(opts ...Option) (*Provider, error) {
	var r Provider

	defaults := []Option{
		WithTimeFunc(nil),
	}

	opts = append(defaults, opts...)

	for _, opt := range opts {
		if opt != nil {
			if err := opt.apply(&r); err != nil {
				return nil, err
			}
		}
	}

	return &r, nil
}

// Roots returns the trusted root certificates for the Trust object.
func (t Provider) Roots() []*x509.Certificate {
	return t.roots
}

// FetchKeys retrieves the public key from the x5c header of the JWS signature
// and verifies the certificate chain against the trusted roots.  If the
// certificate chain is valid and contains all required policies, the public
// key is added to the key sink.  If the certificate chain is invalid or does
// not contain all required policies, an error is returned.
func (t Provider) FetchKeys(ctx context.Context, ks jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	headers := sig.ProtectedHeaders()

	a := headers.Algorithm()
	chain := headers.X509CertChain()

	// Only continue if the algorithm is asymmetric, ignore the others.
	if a == "" || a == jwa.NoSignature || a.IsSymmetric() || chain == nil {
		return nil
	}

	certs, err := chainToCerts(chain)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return ErrUntrustedKey
	}

	// Link the certificate chain against the trusted roots if possible.
	chains, err := t.linkToRoots(certs)
	if err != nil {
		return err
	}

	verified, err := t.verifyChains(ctx, chains)
	if err != nil {
		return err
	}

	// We only care about the leaf node which is always the first cert in any
	// returned chain, so always choose the first.
	ks.Key(a, verified[0].PublicKey)

	return nil
}

// chainToCerts converts the cert.Chain into an array of x509 certificates for
// processing or returns an error.  A nil chain is considered an error.
func chainToCerts(chain *cert.Chain) ([]*x509.Certificate, error) {
	// Decode the certificate chain
	var rv []*x509.Certificate

	for i := 0; i < chain.Len(); i++ {
		certStr, _ := chain.Get(i)

		certData, err := base64.URLEncoding.DecodeString(string(certStr))
		if err != nil {
			return nil, errors.Join(ErrParsingJWS, err)
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, errors.Join(ErrParsingJWS, err)
		}

		rv = append(rv, cert)
	}

	return rv, nil
}

// linkToRoots verifies the certificate chain against the trusted roots and
// returns the chain if it is valid.  If the chain is invalid, an error is
// returned.  There can be multiple valid chains.
func (t Provider) linkToRoots(chain []*x509.Certificate) ([][]*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, root := range t.roots {
		roots.AddCert(root)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	rv, err := chain[0].Verify(
		x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   t.now(),
		})

	if err != nil || rv == nil {
		return nil, errors.Join(err, ErrUntrustedKey)
	}
	return rv, nil
}

// verifyChains verifies the certificate chains against the required verifiers.
func (t Provider) verifyChains(ctx context.Context, chains [][]*x509.Certificate) ([]*x509.Certificate, error) {
	errs := make([]error, 0, len(chains))
	for _, chain := range chains {
		err := t.verifyChain(ctx, chain)
		if err == nil {
			return chain, nil
		}

		errs = append(errs, err)
	}

	errs = append(errs, ErrUntrustedKey)
	return nil, errors.Join(errs...)
}

// verifyChain verifies the certificate chain against the required verifiers.
func (t Provider) verifyChain(ctx context.Context, chain []*x509.Certificate) error {
	for _, verifier := range t.verifiers {
		if err := verifier.Verify(ctx, chain, t.now()); err != nil {
			return err
		}
	}

	return nil
}
