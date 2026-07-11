package verifier

import (
	"crypto/x509"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/templates"
)

// NewNgVerifier constructs a Verifier with an ima-ng template implementation.
func NewNgVerifier(measurementList *measurement.List, attester *attestation.Attester) (*Verifier, error) {
	ng, err := templates.NewNgTemplate(
		attester.TemplateHashAlgo(),
		attester.FileHashAlgo(),
		attester.PCR(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ima-ng template: %w", err)
	}
	return NewVerifier(measurementList, ng, attester), nil
}

// NewSigVerifier constructs a Verifier with an ima-sig template implementation.
func NewSigVerifier(
	measurementList *measurement.List,
	attester *attestation.Attester,
	certs []*x509.Certificate,
) (*Verifier, error) {
	sig, err := templates.NewSigTemplate(
		attester.TemplateHashAlgo(),
		attester.FileHashAlgo(),
		attester.PCR(),
		certs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ima-sig template: %w", err)
	}
	return NewVerifier(measurementList, sig, attester), nil
}
