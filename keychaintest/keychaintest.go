// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package keychaintest provides utilities for generating and managing
// certificate chains for testing purposes. It includes functionality
// for creating certificate chains with configurable parameters, such as
// elliptic curves, validity periods, and descriptions. Each certificate
// in the chain is represented by a Node, which includes both the public
// certificate and the associated private key.

package keychaintest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Chain represents a certificate chain consisting of multiple Nodes.
type Chain []Node

// Leaf returns the leaf certificate (first node) in the chain.
func (c Chain) Leaf() Node {
	return c[0]
}

// Intermediates returns the intermediate certificates in the chain.
func (c Chain) Intermediates() []Node {
	return c[1 : len(c)-1]
}

// Root returns the root certificate (last node) in the chain.
func (c Chain) Root() Node {
	return c[len(c)-1]
}

// Included returns all certificates in the chain except for the root.
func (c Chain) Included() []*x509.Certificate {
	included := c[:len(c)-1]
	certs := make([]*x509.Certificate, len(included))
	for i, node := range included {
		certs[i] = node.Public
	}
	return certs
}

// Node represents a single certificate and its associated private key.
type Node struct {
	Public  *x509.Certificate // Public is the public certificate.
	Private *ecdsa.PrivateKey // Private is the private key associated with the certificate.
}

// config holds the configuration options for generating a certificate chain.
type config struct {
	desc      string         // desc is a description of the configuration.
	curve     elliptic.Curve // curve is the elliptic curve used for key generation.
	notbefore time.Time      // notbefore is the start time for the certificate's validity period.
	notafter  time.Time      // notafter is the end time for the certificate's validity period.
}

// New generates a certificate chain with the given options.
func New(opts ...Option) (Chain, error) {
	var c config

	defaults := []Option{
		EC256(),
		NotBefore(time.Now()),
		NotAfter(time.Now().AddDate(1, 0, 0)),
	}
	vadors := []Option{
		validateTimes(),
	}

	opts = append(defaults, opts...)
	opts = append(opts, vadors...)

	for _, opt := range opts {
		if opt != nil {
			err := opt.apply(&c)
			if err != nil {
				return nil, err
			}
		}
	}

	//func generateCertChain(desc string) ([]*x509.Certificate, *ecdsa.PrivateKey, error) {
	re := regexp.MustCompile(`\s+`)
	description := re.ReplaceAllString(c.desc, "")

	list := strings.Split(description, "<-")

	nodes := make([]Node, len(list))

	var parent Node

	for i := len(list) - 1; i >= 0; i-- {
		priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			return nil, err
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				Organization: []string{fmt.Sprintf("Intermediate %d", len(list)-1-i)},
			},
			NotBefore:             c.notbefore,
			NotAfter:              c.notafter,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  i != 0, // Only the root and intermediate CAs are CAs
			BasicConstraintsValid: true,
		}

		// RootCA
		if i == len(list)-1 {
			template.Subject = pkix.Name{
				Organization: []string{"Root"},
			}
		}

		// Leaf Node
		if i == 0 {
			template.Subject = pkix.Name{
				Organization: []string{"Leaf"},
			}
			template.KeyUsage = x509.KeyUsageDigitalSignature
			template.IsCA = false
		}

		// Add policies as OIDs
		if i != 0 {
			policies := strings.TrimPrefix(strings.TrimSuffix(list[i], ")"), "ica(")
			if policies != list[i] {
				for _, policy := range strings.Split(policies, ",") {
					oid := asn1.ObjectIdentifier{}
					for _, part := range strings.Split(policy, ".") {
						var num int
						_, err := fmt.Sscanf(part, "%d", &num)
						if err != nil {
							return nil, fmt.Errorf("invalid policy OID: %v", policy)
						}
						oid = append(oid, num)
					}
					template.PolicyIdentifiers = append(template.PolicyIdentifiers, oid)
				}
			}
		}

		var certDER []byte
		if parent.Public == nil {
			certDER, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		} else {
			certDER, err = x509.CreateCertificate(rand.Reader, template, parent.Public, &priv.PublicKey, parent.Private)
		}
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}

		nodes[i] = Node{
			Public:  cert,
			Private: priv,
		}

		parent = nodes[i]
	}

	return nodes, nil
}
