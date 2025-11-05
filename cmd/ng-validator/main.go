package main

import (
	"crypto"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	ima "github.com/franc-zar/go-ima/pkg"
)

func main() {
	fs := flag.NewFlagSet("ima-validator", flag.ExitOnError)

	path := fs.String("path", ima.DefaultBinaryPath, "Path to IMA measurement list file")
	expected := fs.String("expected", "", "Expected aggregate digest (hex string)")
	pcrIndex := fs.Int("pcr", 10, "PCR index to validate against")
	templateHash := fs.Int("templateHash", int(crypto.SHA256), "Template hash algorithm (crypto.Hash ID)")
	fileHash := fs.Int("fileHash", int(crypto.SHA256), "File hash algorithm (crypto.Hash ID)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --expected <digest> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	// --- Validate user input ---
	if *expected == "" {
		fmt.Fprintln(os.Stderr, "Error: missing required flag --expected")
		fs.Usage()
		os.Exit(2)
	}

	digest, err := hex.DecodeString(*expected)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid expected digest (must be hex): %v\n", err)
		os.Exit(2)
	}

	ml := ima.NewMeasurementListFromFile(*path, 0)
	err = ml.Open(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read measurement list: %v\n", err)
		os.Exit(1)
	}

	integrity, err := ima.NewIntegrity(
		uint32(*pcrIndex),
		crypto.Hash(*templateHash),
		crypto.Hash(*fileHash),
		nil,
		0,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create integrity context: %v\n", err)
		os.Exit(1)
	}

	validator := ima.NewNgValidator(ml, integrity, nil)

	if err = validator.MeasurementListAttestation(digest); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Attestation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Attestation successful")
}
