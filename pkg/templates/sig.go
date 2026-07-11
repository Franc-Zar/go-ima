package templates

import (
	"crypto/x509"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/fields"
	"github.com/franc-zar/go-ima/pkg/measurement"
)

// SigVerifier verifies ima-sig signatures using a trusted certificate set.
type SigVerifier struct {
	certs []*x509.Certificate
}

// NewSigVerifier creates a SigVerifier with an initial certificate list.
func NewSigVerifier(certs []*x509.Certificate) *SigVerifier {
	if len(certs) == 0 {
		certs = []*x509.Certificate{}
	}
	return &SigVerifier{
		certs: certs,
	}
}

// NewSigVerifierFromPEMFile creates a SigVerifier by loading certificates from a PEM file.
func NewSigVerifierFromPEMFile(filePath string) (*SigVerifier, error) {
	certs, err := crypto.CertsFromPEMFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates from PEM file: %w", err)
	}
	return NewSigVerifier(certs), nil
}

// NewSigVerifierFromPEM creates a SigVerifier from PEM-encoded certificates.
func NewSigVerifierFromPEM(certsPEM []byte) (*SigVerifier, error) {
	certs, err := crypto.CertsFromPEM(certsPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates from PEM: %w", err)
	}
	return NewSigVerifier(certs), nil
}

// NewSigVerifierFromDER creates a SigVerifier from DER-encoded certificates.
func NewSigVerifierFromDER(certsDER []byte) (*SigVerifier, error) {
	certs, err := x509.ParseCertificates(certsDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates from DER: %w", err)
	}
	return NewSigVerifier(certs), nil
}

// AddCert appends cert to the trusted certificate set.
func (sv *SigVerifier) AddCert(cert *x509.Certificate) {
	sv.certs = append(sv.certs, cert)
}

// AddCertFromPEMFile loads certificates from filePath and appends them.
func (sv *SigVerifier) AddCertFromPEMFile(filePath string) error {
	certs, err := crypto.CertsFromPEMFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load certificates from PEM file: %w", err)
	}
	sv.certs = append(sv.certs, certs...)
	return nil
}

// GetCert returns the trusted certificate matching keyID.
func (sv *SigVerifier) GetCert(keyID uint32) (*x509.Certificate, error) {
	for _, cert := range sv.certs {
		certKeyID, err := crypto.IMAKeyID(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to compute IMA key ID from certificate: %w", err)
		}
		if certKeyID == keyID {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("no matching certificate found for key ID: 0x%x", keyID)
}

// Verify checks sig over data using keyID and hashAlgo.
func (sv *SigVerifier) Verify(keyID uint32, data []byte, hashAlgo crypto.IMAHashAlgo, sig []byte) error {
	cert, err := sv.GetCert(keyID)
	if err != nil {
		return fmt.Errorf("failed to find certificate: %w", err)
	}
	return crypto.SigVerify(cert.PublicKey, hashAlgo, data, sig)
}

// NewSigTemplate creates an ima-sig Template with optional signature verification.
func NewSigTemplate(
	templateHashAlgo crypto.IMAHashAlgo,
	fileHashAlgo crypto.IMAHashAlgo,
	pcr uint32,
	certs []*x509.Certificate,
) (*Template, error) {
	sigExtra, err := newSigExtra(fileHashAlgo, certs)
	if err != nil {
		return nil, fmt.Errorf("failed to create sig extra fields: %w", err)
	}
	sig, err := NewTemplate(pcr, []byte("ima-sig"), templateHashAlgo, fileHashAlgo, sigExtra)
	if err != nil {
		return nil, fmt.Errorf("failed to create base Template: %w", err)
	}
	return sig, nil
}

func newSigExtra(hashAlgo crypto.IMAHashAlgo, certs []*x509.Certificate) (*sigExtra, error) {
	fileHash, err := fields.NewDigestNg(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create DigestNg field: %w", err)
	}
	filePath := fields.NewNameNg()
	sig := fields.NewSig()

	var sigVerifier *SigVerifier
	if len(certs) > 0 {
		sigVerifier = NewSigVerifier(certs)
	}

	return &sigExtra{
		fileHash:    fileHash,
		filePath:    filePath,
		sig:         sig,
		sigVerifier: sigVerifier,
	}, nil
}

type sigExtra struct {
	// fileHash is a d-ng IMA field, digest representing the measure of the target file.
	fileHash *fields.DigestNg
	// filePath is a n-ng IMA field, path to the measured file.
	filePath *fields.NameNg
	// sig is a sig IMA field, signature of the target file.
	sig *fields.Sig
	// sigVerifier is used to verify the signature in the sig field.
	sigVerifier *SigVerifier
}

// GetFields returns template fields in the canonical packing order.
func (s *sigExtra) GetFields() []fields.TemplateField {
	return []fields.TemplateField{s.fileHash, s.filePath, s.sig}
}

// Size returns the total encoded size of sig template extra fields.
func (s *sigExtra) Size() int {
	return s.fileHash.Size() + s.filePath.Size() + s.sig.Size()
}

// Parse reads sig template extra fields and optionally verifies signatures.
func (s *sigExtra) Parse(r measurement.FieldReader) error {
	err := s.fileHash.Parse(r)
	if err != nil {
		return fmt.Errorf("failed to parse file hash: %w", err)
	}
	err = s.filePath.Parse(r)
	if err != nil {
		return fmt.Errorf("failed to parse file path: %w", err)
	}
	err = s.sig.Parse(r)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}
	if s.sigVerifier == nil {
		return nil
	}

	sig := s.sig.Value()
	if len(sig) == 0 {
		return nil
	}
	err = s.sigVerifier.Verify(s.sig.KeyID(), s.fileHash.Value(), s.sig.HashAlgo(), sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	return nil
}

// Clear resets parsed sig template extra fields.
func (s *sigExtra) Clear() {
	s.fileHash.Clear()
	s.filePath.Clear()
	s.sig.Clear()
}
