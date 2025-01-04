// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"context"
	"crypto/x509"
	"time"
)

type policiesVerifier struct {
	policies []string
}

func (p *policiesVerifier) Verify(_ context.Context, chain []*x509.Certificate, _ time.Time) error {
	// Check that at least one certificate in the chain contains each of the
	// required policies.
	required := make(map[string]bool, len(p.policies))
	for _, policy := range p.policies {
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
			return ErrMissingPolicy
		}
	}

	return nil
}
