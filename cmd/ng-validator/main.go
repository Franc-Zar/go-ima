package main

import (
	"crypto"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/validator"
	"os"
)

func main() {
	fs := flag.NewFlagSet("ima-v", flag.ExitOnError)

	path := fs.String("path", measurement.DefaultBinaryPath, "Path to IMA measurement list file")
	expected := fs.String("expected", "", "Expected aggregate digest (hex string)")
	pcrIndex := fs.Int("pcr", attestation.DefaultPCRIndex, "PCR index to validate against")
	templateHash := fs.Int("templateHash", int(crypto.SHA256), "Template hash algorithm (crypto.Hash ID)")
	fileHash := fs.Int("fileHash", int(crypto.SHA256), "File hash algorithm (crypto.Hash ID)")

	fs.Usage = func() {
		fmt.Printf("Usage: %s --expected <digest> [options]\n", os.Args[0])
		fmt.Printf("Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	// --- Validate user input ---
	if *expected == "" {
		fmt.Printf("Error: missing required flag --expected")
		fs.Usage()
		os.Exit(2)
	}

	digest, err := hex.DecodeString(*expected)
	if err != nil {
		fmt.Printf("Error: invalid expected digest (must be hex): %v\n", err)
		os.Exit(2)
	}

	ml := measurement.NewMeasurementListFromFile(*path, 0)
	err = ml.Open(0)
	if err != nil {
		fmt.Printf("Error: cannot read measurement list: %v\n", err)
		os.Exit(1)
	}

	integrity, err := attestation.NewIntegrity(
		uint32(*pcrIndex),
		crypto.Hash(*templateHash),
		crypto.Hash(*fileHash),
		nil,
		0,
	)
	if err != nil {
		fmt.Printf("Error: cannot create integrity context: %v\n", err)
		os.Exit(1)
	}

	v := validator.NewNgValidator(ml, integrity, nil)

	if err = v.MeasurementListAttestation(digest); err != nil {
		fmt.Printf("[-] Attestation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Attestation successful")
}
