# keychainjwt

A Go library for handling certificate-based trust chain secured JWS and JWTs.

[![Build Status](https://github.com/xmidt-org/keychainjwt/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/keychainjwt/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/xmidt-org/keychainjwt/graph/badge.svg?token=XvcXIaXcmE)](https://codecov.io/gh/xmidt-org/keychainjwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/keychainjwt)](https://goreportcard.com/report/github.com/xmidt-org/keychainjwt)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/keychainjwt/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/keychainjwt.svg)](https://github.com/xmidt-org/keychainjwt/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/keychainjwt)](https://pkg.go.dev/github.com/xmidt-org/keychainjwt)

## Features

- Extracts and validates the certificate chains from JWS/JWTs against trusted roots.
- Customizable trust policies and options

## Installation

To install the library, use `go get`:

```sh
go get github.com/xmidt-org/keychainjwt
```
