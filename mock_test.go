// SPDX-FileCopyrightText: 2024-2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package jwskeychain

import "github.com/lestrrat-go/jwx/v3/jwa"

type mockKey struct {
	keys []mockKeySet
}

type mockKeySet struct {
	key any
	alg jwa.SignatureAlgorithm
}

func (m *mockKey) Key(alg jwa.SignatureAlgorithm, key any) {
	m.keys = append(m.keys, mockKeySet{
		key: key,
		alg: alg,
	})
}
