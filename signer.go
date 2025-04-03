// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Signer creates a JWS SignVerifyOption that is used to sign a JWS with the
// provided certificate chain, algorithm and private key.  The certificate chain
// is used to set the x5c header in the JWS.
//
// The chain parameter is a slice of x509.Certificate objects that represent
// the certificate chain to be used for signing the JWS.  The first certificate
// in the chain is the leaf certificate and the remaining certificates are the
// intermediates.
//
// If the root certificate is included in the chain, the root certificate is
// detected and is ignored.  The root certificate is not included in the x5c
// header.  The root certificate must be provided to the consumer outside the
// x5c header or JWS/JWT.
func Signer(alg jwa.SignatureAlgorithm, private any, chain []*x509.Certificate) (jws.SignVerifyOption, error) {
	if alg.IsSymmetric() {
		return nil, fmt.Errorf("%w: symmetric algorithms are invalid for a public/private key based signature", ErrInvalidAlg)
	}

	if alg.String() == jwa.NoSignature().String() {
		return nil, fmt.Errorf("%w: jwa.Nosignature is disallowed", ErrInvalidAlg)
	}

	// Build certificate chain.
	var list cert.Chain
	for _, cert := range chain {
		// A certificate is a root CA if:
		// - It is a CA (cert.IsCA is true)
		// - It is self-signed (issuer and subject are the same)
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			continue
		}

		err := list.AddString(base64.URLEncoding.EncodeToString(cert.Raw))
		if err != nil {
			return nil, err
		}
	}

	// This only works if there is at least one certificate.
	if list.Len() < 1 {
		return nil, ErrInvalidx509Chain
	}

	// Create headers and set x5c with certificate chain.
	headers := jws.NewHeaders()
	err := headers.Set(jws.X509CertChainKey, &list)
	if err != nil {
		return nil, err
	}

	return jws.WithKey(alg, private, jws.WithProtectedHeaders(headers)), nil
}
