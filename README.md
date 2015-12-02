### Spartan Go Library

Go API for [spartan](https://github.com/yahoo/spartan)

[![GoDoc](https://godoc.org/github.com/yahoo/spartan-go?status.svg)](https://godoc.org/github.com/yahoo/spartan-go) [![Build Status](https://travis-ci.org/yahoo/spartan-go.svg?branch=master)](https://travis-ci.org/yahoo/spartan-go)

### What's in the box

This library supports fetching a token from spartan Attestation server and
verifying the token received in the request.

This repo also includes a command-line utility which can interact with
Spartan provisioner server

### Getting Started

`GetToken` function to be used on the client side

```go
import "github.com/yahoo/spartan-go"

// GetToken returns a token for the specified role
// and can be used to access the service corresponding to 
// the "SuperRole" role
token, err := spartan.GetToken("SuperRole", tokenOptions)

```

`VerifyToken` function to be used on the server side

```go

import "github.com/yahoo/spartan-go"

// VerifyToken verifies the token received in the request
// to this server
err = spartan.VerifyToken(token, verifyOptions)

```

[app.go][] is a demo app which shows how to invoke these functions

[app.go]: ./demo/app.go
