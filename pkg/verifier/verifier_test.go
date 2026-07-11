package verifier_test

import (
	"testing"

	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/verifier"
	"github.com/stretchr/testify/assert"
)

func TestMeasurementListAttestation_Ng(t *testing.T) {
	t.Parallel()
	ml, err := measurement.NewIMAListFromFile("../../tests/ima_ng", 0)
	if err != nil {
		t.Fatalf("failed to create List from file: %v", err)
	}
	attester, err := attestation.NewAttester(10, crypto.SHA1, crypto.SHA256, 0)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewNgVerifier(ml, attester)
	if err != nil {
		t.Fatalf("failed to create NgValidator: %v", err)
	}
	expected := []byte{
		0xDA, 0x7C, 0xE8, 0x2C, 0x00, 0xA5,
		0x52, 0x64, 0x83, 0x39, 0x10, 0x51, 0xF3,
		0xFB, 0x73, 0x6F, 0xCD, 0xE2, 0x08, 0xCA,
	}
	assert.NoError(t, v.MeasurementListAttestation(expected))
}

func TestMeasurementListAttestation_Sig(t *testing.T) {
	t.Parallel()
	ml, err := measurement.NewIMAListFromFile("../../tests/ima_sig", 0)
	if err != nil {
		t.Fatalf("failed to create List from file: %v", err)
	}
	attester, err := attestation.NewAttester(10, crypto.SHA1, crypto.SHA256, 0)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewSigVerifier(ml, attester, nil)
	if err != nil {
		t.Fatalf("failed to create SigValidator: %v", err)
	}
	expected := []byte{
		0x2C, 0x72, 0xC3, 0xB2, 0x8F, 0x2E, 0x10, 0xBB,
		0x53, 0x89, 0x50, 0x5F, 0x83, 0x6B, 0x45, 0x39,
		0xB9, 0x26, 0xEC, 0xF3,
	}
	assert.NoError(t, v.MeasurementListAttestation(expected))
}

func TestMeasurementListAttestation_Sig_SigVerify(t *testing.T) {
	t.Parallel()
	ml, err := measurement.NewIMAListFromFile("../../tests/ima_sig", 0)
	if err != nil {
		t.Fatalf("failed to create List from file: %v", err)
	}
	attester, err := attestation.NewAttester(10, crypto.SHA1, crypto.SHA256, 0)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	certs, err := crypto.CertsFromPEMFile("../../tests/cert.pem")
	if err != nil {
		t.Fatalf("failed to load certificates: %v", err)
	}
	v, err := verifier.NewSigVerifier(ml, attester, certs)
	if err != nil {
		t.Fatalf("failed to create SigValidator: %v", err)
	}
	expected := []byte{
		0x2C, 0x72, 0xC3, 0xB2, 0x8F, 0x2E, 0x10, 0xBB,
		0x53, 0x89, 0x50, 0x5F, 0x83, 0x6B, 0x45, 0x39,
		0xB9, 0x26, 0xEC, 0xF3,
	}
	assert.NoError(t, v.MeasurementListAttestation(expected))
}
