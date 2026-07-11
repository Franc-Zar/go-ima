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
	attester, err := attestation.NewAttester(
		10,
		crypto.SHA1,
		crypto.SHA256,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewNgVerifier(ml, attester)
	if err != nil {
		t.Fatalf("failed to create NgVerifier: %v", err)
	}
	expected := []byte{
		0xDA, 0x7C, 0xE8, 0x2C, 0x00, 0xA5,
		0x52, 0x64, 0x83, 0x39, 0x10, 0x51, 0xF3,
		0xFB, 0x73, 0x6F, 0xCD, 0xE2, 0x08, 0xCA,
	}
	assert.NoError(t, v.MeasurementListAttestation(expected))
}

func TestMeasurementListAttestation_Ng_twoStepAttestation(t *testing.T) {
	t.Parallel()
	ml, err := measurement.NewIMAListFromFile("../../tests/ima_ng", 0)
	if err != nil {
		t.Fatalf("failed to create List from file: %v", err)
	}
	attester, err := attestation.NewAttester(
		10,
		crypto.SHA1,
		crypto.SHA256,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewNgVerifier(ml, attester)
	if err != nil {
		t.Fatalf("failed to create NgVerifier: %v", err)
	}

	expectFirst := []byte{
		0x16, 0x88, 0xC1, 0xA6, 0xAA, 0x64, 0x8F, 0x69,
		0xBA, 0x4D, 0x8D, 0x0C, 0x51, 0x9D, 0xA9, 0x75,
		0xD7, 0x06, 0x02, 0x4C,
	}

	assert.NoError(t, v.MeasurementListAttestation(expectFirst))

	expectedSecond := []byte{
		0xDA, 0x7C, 0xE8, 0x2C, 0x00, 0xA5,
		0x52, 0x64, 0x83, 0x39, 0x10, 0x51, 0xF3,
		0xFB, 0x73, 0x6F, 0xCD, 0xE2, 0x08, 0xCA,
	}
	assert.NoError(t, v.MeasurementListAttestation(expectedSecond))
}

func TestMeasurementListAttestation_Ng_fromTheMiddle(t *testing.T) {
	t.Parallel()
	ml, err := measurement.NewIMAListFromFile("../../tests/ima_ng", 0)
	if err != nil {
		t.Fatalf("failed to create List from file: %v", err)
	}

	alreadyAttested := int64(26767) // Example offset to start attestation from the middle
	aggregate := []byte{
		0x16, 0x88, 0xC1, 0xA6, 0xAA, 0x64, 0x8F, 0x69,
		0xBA, 0x4D, 0x8D, 0x0C, 0x51, 0x9D, 0xA9, 0x75,
		0xD7, 0x06, 0x02, 0x4C,
	} // Example aggregate value at that offset

	attester, err := attestation.NewAttester(
		10,
		crypto.SHA1,
		crypto.SHA256,
		alreadyAttested,
		aggregate,
	)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewNgVerifier(ml, attester)
	if err != nil {
		t.Fatalf("failed to create NgVerifier: %v", err)
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
	attester, err := attestation.NewAttester(
		10,
		crypto.SHA1,
		crypto.SHA256,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	v, err := verifier.NewSigVerifier(ml, attester, nil)
	if err != nil {
		t.Fatalf("failed to create SigVerifier: %v", err)
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
	attester, err := attestation.NewAttester(
		10,
		crypto.SHA1,
		crypto.SHA256,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create Attester: %v", err)
	}
	certs, err := crypto.CertsFromPEMFile("../../tests/cert.pem")
	if err != nil {
		t.Fatalf("failed to load certificates: %v", err)
	}
	v, err := verifier.NewSigVerifier(ml, attester, certs)
	if err != nil {
		t.Fatalf("failed to create SigVerifier: %v", err)
	}
	expected := []byte{
		0x2C, 0x72, 0xC3, 0xB2, 0x8F, 0x2E, 0x10, 0xBB,
		0x53, 0x89, 0x50, 0x5F, 0x83, 0x6B, 0x45, 0x39,
		0xB9, 0x26, 0xEC, 0xF3,
	}
	assert.NoError(t, v.MeasurementListAttestation(expected))
}
