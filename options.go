// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychainjwt

import (
	"crypto/x509"
	"time"
)

// Option is an interface that defines a function to apply an option to a Trust object.
type Option interface {
	apply(*Trust)
}

// optionFunc is a function that applies an option to a Trust object.
type optionFunc func(*Trust)

func (f optionFunc) apply(r *Trust) {
	f(r)
}

// RequirePolicies sets the required policies for the Trust object.
func RequirePolicies(policies ...string) Option {
	return optionFunc(
		func(t *Trust) {
			t.policies = append(t.policies, policies...)
		})
}

// TrustedRoots adds the provided root certificates to the Trust object.
func TrustedRoots(cert ...*x509.Certificate) Option {
	return optionFunc(
		func(t *Trust) {
			t.roots = append(t.roots, cert...)
		})
}

// WithTimeFunc sets the function to retrieve the current time for the Trust object.
func WithTimeFunc(now func() time.Time) Option {
	return optionFunc(
		func(t *Trust) {
			if now == nil {
				now = time.Now
			}
			t.now = now
		})
}
