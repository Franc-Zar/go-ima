package fields

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/measurement"
)

const (
	// NameSize is the fixed size of the "n" field in the original IMA template, which is 256 bytes (including the 0-padding).
	NameSize = 256
	// DigestSize is the fixed size of the "d" field in the original IMA template, which is 20 bytes (MD5 or SHA1 digest).
	DigestSize = 20

	// MinPCRIndex is the minimum valid PCR index for TPM 2.0.
	// PCRs 0-9 are reserved for boot measurements.
	// PCR 10 is the first PCR available for general purpose use.
	MinPCRIndex = 10
	// MaxPCRIndex is the maximum valid PCR index for TPM 2.0.
	MaxPCRIndex = 23
	// DefaultPCRIndex is the default TPM's PCR index
	// reserved for IMA aggregate extensions.
	DefaultPCRIndex = 10

	// IMADigSigType is the magic header for all IMA signatures.
	IMADigSigType = 0x03
	// SigV2 is the second version of the IMA signature field format.
	// It operates signing the ima_digest_data
	// https://codebrowser.dev/linux/linux/security/integrity/integrity.h.html#ima_digest_data
	SigV2 = 0x02
	// SigV3 is the third version of the IMA signature field format.
	// It operates signing the ima_file_id
	// https://codebrowser.dev/linux/linux/security/integrity/integrity.h.html#ima_file_id
	SigV3 = 0x03
	// SigHeaderSize SigV2 and SigV3 share the same header structure.
	// sigType(1) + version(1) + hashAlgo(1) + keyID(4) + sigSize(2).
	SigHeaderSize = 9
)

// TemplateField interface represents common properties and behaviors of IMA template extra fields.
// https://docs.kernel.org/security/IMA-templates.html
type TemplateField interface {
	// ID returns the IMA identifier of the field (e.g., "d-ng", "n-ng").
	ID() string
	// Value returns the raw byte representation of the field.
	Value() []byte
	// Pack serializes the field value for template hash recomputation.
	Pack() ([]byte, error)
	// Parse reads the field value from the provided FieldReader and populates the field's value.
	// Parsing logic must include validation of the field's structure according to its expected constraints
	// (e.g., length, format, expected values) according to the IMA specification.
	Parse(r measurement.FieldReader) error
	// Size returns the byte size of the field,
	// including its prefix-length field if applicable.
	Size() int
	// String returns the human-readable string representation of the field.
	String() string
	// Clear resets the field value to its zero value.
	Clear()
}

// Digest represents the "d" field of the original IMA template,
// which contains the file hash digest of the measured file.
// It only supports MD5 and SHA1 (digest size=20), as these are the only hash algorithms
// allowed for file hashing in the original IMA template.
type Digest struct {
	hashAlgo crypto.IMAHashAlgo
	digest   [DigestSize]byte
}

func NewDigest(hashAlgo crypto.IMAHashAlgo) (*Digest, error) {
	if hashAlgo != crypto.MD5 && hashAlgo != crypto.SHA1 {
		return nil, fmt.Errorf("invalid hash algorithm for Digest field: %v", hashAlgo)
	}
	return &Digest{
		hashAlgo: hashAlgo,
	}, nil
}

func (d *Digest) ID() string {
	return "d"
}

func (d *Digest) Value() [DigestSize]byte {
	return d.digest
}

func (d *Digest) Pack() ([]byte, error) {
	return PackRaw(d.digest[:])
}

func (d *Digest) Parse(r measurement.FieldReader) error {
	hashValue, err := r.ReadFixed(d.hashAlgo.Size())
	if err != nil {
		return fmt.Errorf("failed to read digest field: %w", err)
	}
	if len(hashValue) != d.hashAlgo.Size() {
		return fmt.Errorf("invalid hash value length: got %d, want %d for hash algorithm %s",
			len(hashValue), d.hashAlgo.Size(), d.hashAlgo.String())
	}
	copy(d.digest[:], hashValue)
	return nil
}

func (d *Digest) Size() int {
	return len(d.digest)
}

func (d *Digest) String() string {
	if len(d.digest) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", d.digest)
}

func (d *Digest) Clear() {
	for i := range d.digest {
		d.digest[i] = 0
	}
}

// Name represents the "n" field of the original IMA template, which contains the null-terminated name of the measured file.
type Name struct {
	name [NameSize]byte
}

func NewName() *Name {
	return &Name{}
}

func (n *Name) ID() string {
	return "n"
}

func (n *Name) Value() [NameSize]byte {
	return n.name
}

func (n *Name) Pack() ([]byte, error) {
	return PackRaw(n.name[:])
}

func (n *Name) Parse(r measurement.FieldReader) error {
	name, err := r.ReadFixed(NameSize)
	if err != nil {
		return fmt.Errorf("failed to read name field: %w", err)
	}
	if len(name) != NameSize {
		return fmt.Errorf("invalid name field length: got %d, want %d", len(name), NameSize)
	}
	// Verify that the name is 0-padded
	_, err = ValidatePadding(name, measurement.NullByte)
	if err != nil {
		return fmt.Errorf("invalid name field: %w", err)
	}
	copy(n.name[:], name)
	return nil
}

func (n *Name) Size() int {
	return len(n.name)
}

func (n *Name) String() string {
	if len(n.name) == 0 {
		return ""
	}
	start, err := ValidatePadding(n.name[:], measurement.NullByte)
	if err != nil {
		return "invalid name"
	}
	return string(n.name[:start])
}

func (n *Name) Clear() {
	n.name = [NameSize]byte{}
}

type NameNg struct {
	name []byte
}

func NewNameNg() *NameNg {
	return &NameNg{}
}

func (n *NameNg) ID() string {
	return "n-ng"
}

func (n *NameNg) Value() []byte {
	return n.name
}

func (n *NameNg) Pack() ([]byte, error) {
	return PackRaw(n.name)
}

func (n *NameNg) Parse(r measurement.FieldReader) error {
	name, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read n-ng field: %w", err)
	}
	// Verify that the name is 0-padded
	start, err := ValidatePadding(name, measurement.NullByte)
	if err != nil {
		return fmt.Errorf("invalid name field: %w", err)
	}
	// n-ng field is a null-terminated string, so the
	// null terminator must be at the end of the name
	if start != len(name)-1 {
		return errors.New("invalid name field: expected null terminator at the end")
	}
	n.name = bytes.Clone(name)
	return nil
}

func (n *NameNg) Size() int {
	return measurement.IMALenFieldSize + len(n.name)
}

func (n *NameNg) String() string {
	if len(n.name) == 0 {
		return ""
	}
	start, err := ValidatePadding(n.name, measurement.NullByte)
	if err != nil || start != len(n.name)-1 {
		return "invalid name"
	}
	return string(n.name[:start])
}

func (n *NameNg) Clear() {
	n.name = nil
}

// DigestNg represents the "d-ng" field of the ima-ng template, which contains the file hash digest of
// the measured file using any hash algorithm allowed for file hashing in ima-ng templates.
type DigestNg struct {
	hashAlgo crypto.IMAHashAlgo
	rawValue []byte
	digest   []byte
}

func NewDigestNg(hashAlgo crypto.IMAHashAlgo) (*DigestNg, error) {
	if !hashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("invalid hash algorithm for DigestNg field: %v", hashAlgo)
	}
	return &DigestNg{
		hashAlgo: hashAlgo,
		digest:   make([]byte, hashAlgo.Size()),
	}, nil
}

func (d *DigestNg) ID() string {
	return "d-ng"
}

func (d *DigestNg) Value() []byte {
	return d.digest
}

func (d *DigestNg) Pack() ([]byte, error) {
	return PackRaw(d.rawValue)
}

func (d *DigestNg) Parse(r measurement.FieldReader) error {
	parsed, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read d-ng field: %w", err)
	}

	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	digest, err := ValidateFileHash(parsed, d.hashAlgo)
	if err != nil {
		return fmt.Errorf("invalid file hash field: %w", err)
	}
	d.rawValue = bytes.Clone(parsed)
	d.digest = bytes.Clone(digest)
	return nil
}

func (d *DigestNg) Size() int {
	return measurement.IMALenFieldSize + len(d.rawValue)
}

func (d *DigestNg) String() string {
	if len(d.digest) == 0 {
		return ""
	}
	// d-ng string structure is <hashAlgoField>:<digest>
	return fmt.Sprintf("%s:%x", d.hashAlgo.String(), d.digest)
}

func (d *DigestNg) Clear() {
	d.digest = nil
	d.rawValue = nil
}

type DigestType string

const (
	Ima    DigestType = "ima"
	Verity DigestType = "verity"
)

func (dt DigestType) String() string {
	return string(dt)
}

func ValidateDigestType(dt DigestType) bool {
	switch dt {
	case Ima, Verity:
		return true
	default:
		return false
	}
}

type DigestNgV2 struct {
	digestType DigestType
	hashAlgo   crypto.IMAHashAlgo
	rawValue   []byte
	digest     []byte
}

func NewDigestNgV2(digestType DigestType, hashAlgo crypto.IMAHashAlgo) (*DigestNgV2, error) {
	if !ValidateDigestType(digestType) {
		return nil, fmt.Errorf("invalid digest type: %s", digestType)
	}
	if !hashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("invalid hash algorithm for file hashing: %v", hashAlgo)
	}
	return &DigestNgV2{
		digestType: digestType,
		hashAlgo:   hashAlgo,
		digest:     make([]byte, hashAlgo.Size()),
	}, nil
}

func (d *DigestNgV2) ID() string {
	return "d-ngv2"
}

func (d *DigestNgV2) Value() []byte {
	return d.digest
}

func (d *DigestNgV2) Pack() ([]byte, error) {
	return PackRaw(d.rawValue)
}

func (d *DigestNgV2) Parse(r measurement.FieldReader) error {
	parsed, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read d-ngv2 field: %w", err)
	}
	// fileHash structure is <digestType>:<hashAlgoField>:<NULL_BYTE><digest>
	digest, err := ValidateFileHashV2(parsed, d.hashAlgo, d.digestType)
	if err != nil {
		return fmt.Errorf("invalid file hash field: %w", err)
	}
	d.rawValue = bytes.Clone(parsed)
	d.digest = bytes.Clone(digest)
	return nil
}

func (d *DigestNgV2) Size() int {
	return measurement.IMALenFieldSize + len(d.rawValue)
}

func (d *DigestNgV2) String() string {
	if len(d.digest) == 0 {
		return ""
	}
	// d-ngv2 string structure is <digestType>:<hashAlgoField>:<digest>
	return fmt.Sprintf("%s:%s:%x", d.digestType, d.hashAlgo.String(), d.digest)
}

func (d *DigestNgV2) Clear() {
	d.digest = nil
	d.rawValue = nil
}

type Sig struct {
	rawValue []byte
	version  uint8
	hashAlgo crypto.IMAHashAlgo
	keyID    uint32
	sig      []byte
}

func NewSig() *Sig {
	return &Sig{}
}

func (s *Sig) ID() string {
	return "sig"
}

func (s *Sig) Value() []byte {
	return s.sig
}

func (s *Sig) KeyID() uint32 {
	return s.keyID
}

func (s *Sig) HashAlgo() crypto.IMAHashAlgo {
	return s.hashAlgo
}

func (s *Sig) Pack() ([]byte, error) {
	return PackRaw(s.rawValue)
}

func (s *Sig) Parse(r measurement.FieldReader) error {
	parsed, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read signature header: %w", err)
	}
	if len(parsed) == 0 {
		// No signature present, return without error
		return nil
	}
	s.version, s.hashAlgo, s.keyID, s.sig, err = ValidateSig(parsed)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	s.rawValue = bytes.Clone(parsed)

	return nil
}

func (s *Sig) Size() int {
	size := measurement.IMALenFieldSize
	sigLen := len(s.sig)
	if sigLen > 0 {
		size += SigHeaderSize + sigLen
	}
	return size
}

func (s *Sig) String() string {
	sigID, err := s.hashAlgo.ToIMASigHashID()
	if err != nil {
		return ""
	}
	sigLen := len(s.sig)
	if sigLen < 0 || sigLen > math.MaxUint16 {
		return ""
	}
	sigSize := uint16(sigLen)

	return fmt.Sprintf("%x%x%x%x%x", IMADigSigType, s.version, sigID, s.keyID, sigSize)
}

func (s *Sig) Clear() {
	s.keyID = 0
	s.sig = nil
	s.rawValue = nil
}
