// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package keychaintest

import (
	"crypto/elliptic"
	"errors"
	"time"
)

type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error {
	return f(c)
}

// Desc provides a string that describes the chain in the following format:
// leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root
// The chain is generated in the order of root, ica(1.2.100), ica(1.2.900, 1.2.901), leaf.
// The root certificate is self-signed and the rest are signed by the previous certificate in the chain.
// The leaf certificate is signed by the last ica in the chain.
// The policies are added to the certificate as Extended Key Usages.
func Desc(description string) Option {
	return optionFunc(
		func(c *config) error {
			c.desc = description
			return nil
		})
}

func EC256() Option {
	return optionFunc(
		func(c *config) error {
			c.curve = elliptic.P256()
			return nil
		})
}

func EC384() Option {
	return optionFunc(
		func(c *config) error {
			c.curve = elliptic.P384()
			return nil
		})
}

func EC521() Option {
	return optionFunc(
		func(c *config) error {
			c.curve = elliptic.P521()
			return nil
		})
}

func NotBefore(t time.Time) Option {
	return optionFunc(
		func(c *config) error {
			c.notbefore = t
			return nil
		})
}

func NotAfter(t time.Time) Option {
	return optionFunc(
		func(c *config) error {
			c.notafter = t
			return nil
		})
}

func validateTimes() Option {
	return optionFunc(
		func(c *config) error {
			var err error
			if c.notafter.Compare(c.notbefore) <= 0 {
				err = errors.New("certificate time is never valid")
			}
			return err
		})
}
