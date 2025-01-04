// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"context"
	"crypto/x509"
	"time"
)

// Option is an interface that defines a function to apply an option to a Trust object.
type Option interface {
	apply(*Provider) error
}

// optionFunc is a function that applies an option to a Trust object.
type optionFunc func(*Provider) error

func (f optionFunc) apply(r *Provider) error {
	return f(r)
}

// errOption returns an error option.
func errOption(err error) Option {
	return errorOption{err}
}

type errorOption struct {
	err error
}

func (e errorOption) apply(*Provider) error {
	return e.err
}

// Verifier is an interface that defines a function to verify a certificate chain.
type Verifier interface {
	Verify(ctx context.Context, chain []*x509.Certificate, now time.Time) error
}

// VerifierFunc is a function that verifies a certificate chain.
type VerifierFunc func(ctx context.Context, chain []*x509.Certificate, now time.Time) error

func (f VerifierFunc) Verify(ctx context.Context, chain []*x509.Certificate, now time.Time) error {
	return f(ctx, chain, now)
}

// Require sets a verifier to be used for additional verification of the certificate chain.
func Require(v Verifier) Option {
	return optionFunc(
		func(t *Provider) error {
			if v != nil {
				t.verifiers = append(t.verifiers, v)
			}
			return nil
		})
}

// RequirePolicies sets the required policies for the Trust object.
func RequirePolicies(policies ...string) Option {
	return Require(&policiesVerifier{policies})
}

// TrustedRoots adds the provided root certificates to the Trust object.
func TrustedRoots(cert ...*x509.Certificate) Option {
	return optionFunc(
		func(t *Provider) error {
			t.roots = append(t.roots, cert...)
			return nil
		})
}

// WithTimeFunc sets the function to retrieve the current time for the Trust object.
func WithTimeFunc(now func() time.Time) Option {
	return optionFunc(
		func(t *Provider) error {
			if now == nil {
				now = time.Now
			}
			t.now = now
			return nil
		})
}
