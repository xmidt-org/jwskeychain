// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychaintest

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateCertChain tests the generateCertChain function.
func TestNew(t *testing.T) {
	errUnknown := errors.New("unknown")
	tests := []struct {
		desc     string
		opts     []Option
		expected []string
		err      error
	}{
		{
			desc:     "leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root",
			expected: []string{"Leaf", "Intermediate 2", "Intermediate 1", "Root"},
		}, {
			desc:     "leaf<-ica(1.2.100)<-root",
			expected: []string{"Leaf", "Intermediate 1", "Root"},
		}, {
			desc: "with ES384 curve",
			opts: []Option{
				Desc("leaf<-ica(1.2.100)<-root"),
				EC384(),
			},
			expected: []string{"Leaf", "Intermediate 1", "Root"},
		}, {
			desc: "with ES521 curve",
			opts: []Option{
				Desc("leaf<-ica(1.2.100)<-root"),
				EC521(),
			},
			expected: []string{"Leaf", "Intermediate 1", "Root"},
		}, {
			desc: `leaf<-
						ica(1.2.100) <-ica
							<-ica
							<-ica<-
							root`,
			expected: []string{"Leaf", "Intermediate 4", "Intermediate 3", "Intermediate 2", "Intermediate 1", "Root"},
		}, {
			desc: "invalid times",
			opts: []Option{
				NotAfter(time.Now()),
				NotBefore((time.Now().Add(time.Second))),
			},
			err: errUnknown,
		}, {
			desc: "leaf<-ica(1.2.invalid)<-root",
			err:  errUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			opts := tt.opts
			if len(opts) == 0 {
				opts = append(opts, Desc(tt.desc))
			}
			chain, err := New(opts...)

			if tt.err != nil {
				assert.Nil(chain)
				require.Error(err)
				if !errors.Is(tt.err, errUnknown) {
					require.ErrorIs(err, tt.err)
				}
				return
			}
			require.NoError(err)

			assert.Len(chain, len(tt.expected))

			for i, cert := range chain {
				assert.Equal(tt.expected[i], cert.Public.Subject.Organization[0])
			}

			re := regexp.MustCompile(`\s+`)
			desc := re.ReplaceAllString(tt.desc, "")

			// Verify policies
			for i, node := range strings.Split(desc, "<-") {
				if strings.Contains(node, "ica(") {
					policies := strings.TrimPrefix(strings.TrimSuffix(node, ")"), "ica(")
					for _, policy := range strings.Split(policies, ",") {
						oid := asn1.ObjectIdentifier{}
						for _, part := range strings.Split(policy, ".") {
							var num int
							n, err := fmt.Sscanf(part, "%d", &num)
							require.NoError(err)
							require.Equal(1, n)
							oid = append(oid, num)
						}

						found := false
						for _, certPolicy := range chain[i].Public.PolicyIdentifiers {
							if certPolicy.Equal(oid) {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("expected policy %v in certificate %d, but not found", oid, i)
						}
					}
				}
			}
		})
	}
}

func mustGeneratecertChain(desc string) Chain {
	chain, err := New(Desc(desc))
	if err != nil {
		panic(err)
	}

	return chain
}

func TestMustGenerateChain(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	got := mustGeneratecertChain("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root")

	require.NotNil(got)
	require.Len(got, 4)

	leaf := got.Leaf()
	require.NotEmpty(&leaf)
	require.NotNil(leaf.Public)
	require.NotNil(leaf.Private)
	assert.Equal("Leaf", leaf.Public.Subject.Organization[0])
	assert.Equal("Leaf", got[0].Public.Subject.Organization[0])

	root := got.Root()
	require.NotEmpty(&root)
	require.NotNil(root.Public)
	require.NotNil(root.Private)
	assert.Equal("Root", root.Public.Subject.Organization[0])
	assert.Equal("Root", got[3].Public.Subject.Organization[0])

	ints := got.Intermediates()
	assert.Equal("Intermediate 2", got[1].Public.Subject.Organization[0])
	assert.Equal("Intermediate 2", ints[0].Public.Subject.Organization[0])
	assert.Equal("Intermediate 1", got[2].Public.Subject.Organization[0])
	assert.Equal("Intermediate 1", ints[1].Public.Subject.Organization[0])

	included := got.Included()
	assert.Equal("Leaf", included[0].Subject.Organization[0])
	assert.Equal("Intermediate 2", included[1].Subject.Organization[0])
	assert.Equal("Intermediate 1", included[2].Subject.Organization[0])

}
