# jwskeychain

A Go library for handling certificate-based trust chain secured JWS and JWTs.

[![Build Status](https://github.com/xmidt-org/jwskeychain/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/jwskeychain/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/xmidt-org/jwskeychain/graph/badge.svg?token=AX7eNV08AD)](https://codecov.io/gh/xmidt-org/jwskeychain)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/jwskeychain)](https://goreportcard.com/report/github.com/xmidt-org/jwskeychain)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/jwskeychain/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/jwskeychain.svg)](https://github.com/xmidt-org/jwskeychain/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/jwskeychain)](https://pkg.go.dev/github.com/xmidt-org/jwskeychain)

## Features

- Extracts and validates the certificate chains from JWS/JWTs against trusted roots.
- Customizable trust policies and options

## Installation

To install the library, use `go get`:

```sh
go get github.com/xmidt-org/jwskeychain
```
