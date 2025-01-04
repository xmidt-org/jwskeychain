// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import "errors"

var (
	// Deprecated: ErrUntrustedKey is no longer used and will be removed in future versions.
	ErrUntrustedKey = errors.New("untrusted key")

	// ErrParsingJWS is returned when there is an error parsing the JWS.
	ErrParsingJWS = errors.New("error parsing jws")

	// ErrMissingPolicy is returned when a required policy is missing from the
	// certificate chain.
	ErrMissingPolicy = errors.New("missing policy")
)
