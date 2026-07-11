package crypto

import (
	"crypto"
	"crypto/rsa"

	//nolint: gosec // ignore the security linter for sha1 as it is used for IMA hash algorithms
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func CertsFromPEMFile(pemFilePath string) ([]*x509.Certificate, error) {
	pemData, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}
	return CertsFromPEM(pemData)
}

func CertsFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		pemData = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM data")
	}

	return certs, nil
}

// IMAKeyID computes the IMA key identifier from an X.509 certificate.
// IMA keyid = last 4 bytes of SHA1(DER-encoded SubjectPublicKeyInfo),
// interpreted as big-endian uint32.
// This matches how evmctl and the kernel derive the keyid.
func IMAKeyID(cert *x509.Certificate) (uint32, error) {
	// use Subject Key Identifier if present — kernel prefers this
	//nolint:mnd // minimum desired length of SubjectKeyId is 4 bytes
	if len(cert.SubjectKeyId) >= 4 {
		id := cert.SubjectKeyId
		return binary.LittleEndian.Uint32(id[len(id)-4:]), nil
	}

	// fallback: SHA1 of DER-encoded public key
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("marshal public key: %w", err)
	}
	//nolint:gosec // G401: SHA-1 is required by the Linux IMA key ID specification.
	h := sha1.Sum(pubKeyDER)
	return binary.LittleEndian.Uint32(h[16:20]), nil // last 4 bytes
}

func SigVerify(pk crypto.PublicKey, hashAlgo IMAHashAlgo, data, sig []byte) error {
	var err error
	switch pk := pk.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pk, hashAlgo.ToCryptoHash(), data, sig)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pk)
	}

	return nil
}
