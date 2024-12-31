// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychainjwt

import "errors"

var (
	ErrUnexpectedSigner = errors.New("expected exactly one signer")
	ErrMissingHeader    = errors.New("header is missing")
	ErrDisallowedAlg    = errors.New("disallowed alg type")
	ErrDecodingCert     = errors.New("decoding cert error")
	ErrParsingCert      = errors.New("cert parsing error")
	ErrInvalidCert      = errors.New("invalid cert")
	ErrMissingPolicy    = errors.New("missing policy")
	ErrParsingJWT       = errors.New("invalid jwt")
	ErrValidatingChain  = errors.New("chain validation problem")
)
