# go-ima

go-ima is a Go library to parse and verify Linux IMA binary measurement lists.
It currently provides end-to-end attestation flows for `ima-ng` and `ima-sig` entries, including optional `ima-sig` signature verification against trusted X.509 certificates.

[![Go Reference](https://pkg.go.dev/badge/github.com/franc-zar/go-ima.svg)](https://pkg.go.dev/github.com/franc-zar/go-ima)
[![Go Report Card](https://goreportcard.com/badge/github.com/franc-zar/go-ima)](https://goreportcard.com/report/github.com/franc-zar/go-ima)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

## What It Does

- Parses IMA binary measurement list entries from file or raw bytes.
- Validates each entry by recomputing and checking the template hash.
- Replays PCR-style aggregate extension (`hash(aggregate || template_hash)`).
- Supports incremental attestation by resuming from a stored byte offset and aggregate.
- Verifies `ima-sig` entry signatures when trusted certificates are provided.

## Current Support

### Templates

- `ima-ng` (`d-ng | n-ng`)
- `ima-sig` (`d-ng | n-ng | sig`)

### Hash Algorithms

- Template/PCR hash: `sha1`, `sha256`, `sha384`, `sha512`
- File hash (`d-ng`): `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`

### Signature Verification

- Signature field versions: v2 and v3 headers are parsed
- Public key type: RSA (`PKCS#1 v1.5` verify path)

## Installation

```bash
go get github.com/franc-zar/go-ima
```

## Quick Start

### Verify an `ima-ng` measurement list against expected PCR aggregate

```go
package main

import (
    "fmt"
    "log"

    "github.com/franc-zar/go-ima/pkg/attestation"
    "github.com/franc-zar/go-ima/pkg/crypto"
    "github.com/franc-zar/go-ima/pkg/fields"
    "github.com/franc-zar/go-ima/pkg/measurement"
    "github.com/franc-zar/go-ima/pkg/verifier"
)

func main() {
    ml, err := measurement.NewIMAListFromFile(
        measurement.DefaultBinaryPath,
        0,
    )
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        _ = ml.Close()
    }()

    att, err := attestation.NewAttester(
        fields.DefaultPCRIndex,
        crypto.SHA1,
        crypto.SHA256,
        0,
        nil,
    )
    if err != nil {
        log.Fatal(err)
    }

    v, err := verifier.NewNgVerifier(ml, att)
    if err != nil {
        log.Fatal(err)
    }

    // Replace with PCR10 aggregate from a trusted TPM quote.
    expected := []byte{0xda, 0x7c, 0xe8, 0x2c, 0x00, 0xa5, 0x52, 0x64, 0x83, 0x39, 0x10, 0x51, 0xf3, 0xfb, 0x73, 0x6f, 0xcd, 0xe2, 0x08, 0xca}

    if err := v.MeasurementListAttestation(expected); err != nil {
        log.Fatalf("attestation failed: %v", err)
    }

    fmt.Printf("verified, attested_offset=%d\n", v.Attester().Attested())
}
```

### Verify `ima-sig` entries with certificates

```go
package main

import (
    "log"

    "github.com/franc-zar/go-ima/pkg/attestation"
    "github.com/franc-zar/go-ima/pkg/crypto"
    "github.com/franc-zar/go-ima/pkg/fields"
    "github.com/franc-zar/go-ima/pkg/measurement"
    "github.com/franc-zar/go-ima/pkg/verifier"
)

func main() {
    ml, err := measurement.NewIMAListFromFile("tests/ima_sig", 0)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        _ = ml.Close()
    }()

    att, err := attestation.NewAttester(
        fields.DefaultPCRIndex,
        crypto.SHA1,
        crypto.SHA256,
        0,
        nil,
    )
    if err != nil {
        log.Fatal(err)
    }

    certs, err := crypto.CertsFromPEMFile("tests/cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    v, err := verifier.NewSigVerifier(ml, att, certs)
    if err != nil {
        log.Fatal(err)
    }

    expected := []byte{0x2c, 0x72, 0xc3, 0xb2, 0x8f, 0x2e, 0x10, 0xbb, 0x53, 0x89, 0x50, 0x5f, 0x83, 0x6b, 0x45, 0x39, 0xb9, 0x26, 0xec, 0xf3}

    if err := v.MeasurementListAttestation(expected); err != nil {
        log.Fatalf("attestation/signature verification failed: %v", err)
    }
}
```

### Incremental attestation (resume from previous state)

`Attester` stores both:

- `Attested()` byte offset inside the measurement list
- `Aggregate()` running PCR aggregate

Persist these values and pass them into a new `attestation.NewAttester(...)` call in the next cycle to attest only new entries.

## Package Layout

```
pkg/
  attestation/   Attester state and aggregate extension logic
  crypto/        IMA hash helpers, certificate loading, signature verification
  fields/        IMA field parsers and validators (d-ng, n-ng, sig, ...)
  measurement/   Measurement list reader abstraction (file/raw)
  templates/     Template assembly and per-entry validation
  verifier/      High-level attestation flow over a measurement list
tests/
  ima_ng         Real binary ima-ng measurement list sample
  ima_sig        Real binary ima-sig measurement list sample
  cert.pem       Certificate used in signature verification tests
```


## Notes

- The verifier intentionally loops until aggregate match or list exhaustion to handle quote/list timing skew.

## Documentation

- Module and package docs: https://pkg.go.dev/github.com/franc-zar/go-ima

## License

Apache 2.0. See [LICENSE](LICENSE).