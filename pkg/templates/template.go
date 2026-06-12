package templates

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/fields"
	"github.com/franc-zar/go-ima/pkg/measurement"
)

// IMA templates are the different formats in which IMA records can be stored in the measurement list.
// Each template has a specific structure and set of fields, but they all share a common base structure:
//
// | PCR (4 bytes) | -> integer representing the PCR index IMA events are extended to (10 is the IMA default).
// | Template Hash (variable size) | -> hash digest of the template fields, used for integrity verification.
// 										The size of this field depends on the hash algorithm used for the template hash by IMA
// 										(SHA1 is the IMA default).
// | Template Name Length (4 bytes) | -> length of the template name field.
// | Template Name (variable size) | -> name of the template, used to identify the IMA template in use.
//
// | Template-specific Fields Length (4 bytes) | -> sum of the template-specific fields and length fields (i.e., 4 bytes * number of fields + sum of field lengths).
// | Template Field 0 Length (4 bytes) | -> length of the first template-specific field.
// | Template Field 0 (variable size) | -> content of the first template-specific field, whose size is specified by the preceding length field.
// | ... |
// | Template Field N Length (4 bytes) | -> length of the N-th template-specific field.
// | Template Field N (variable size) | -> content of the N-th template-specific field, whose size is specified by the preceding length field.
//
// | file Hash Length (4 bytes) | -> size of the digest according to algorithm used by IMA to hash file content (e.g., 32 for sha256, 64 for sha512).
// | file Hash (variable size) | -> content of the file hash field, whose size is specified by the preceding length field,
// 									and whose structure is <hashAlgoField>:<NULL_BYTE><digest> (e.g., sha256:<NULL_BYTE><32-byte digest>).
// | file Path Length (4 bytes) | -> length of the file path string, including the NULL terminator.
// | file Path (variable size) | -> the actual path of the file being measured, including the NULL terminator.
//
// The BaseFields interface defines the common fields and parsing logic for all templates, while the SpecificFields
// interface defines the contract for the template-specific fields.
//
// Each template (e.g., ima-ng, ima-sig) implements the Template interface by embedding BasicEntry for the base
// fields and implementing the SpecificFields interface for its specific fields.

// BaseFields exposes the parsed header fields that all templates share.
// Implemented by *BasicEntry — templates get this for free via embedding.
// PCR | templateHash | templateName is the common base structure of all IMA templates.
type BaseFields interface {
	// PCR returns the PCR index field of the entry.
	PCR() uint32
	// TemplateHash returns the template hash field of the entry.
	TemplateHash() []byte
	// TemplateName returns the template name field of the entry.
	TemplateName() []byte
	// Parse reads the base fields (PCR, template hash, template name) from the provided FieldReader.
	// pcr is used to validate the PCR value in the entry; it should be set to the expected PCR index for the template.
	// templateHashSize is used to validate the length of the template hash field in the entry; it should be set to the expected hash size for the template's hash algorithm.
	// templateName is used to validate the template name field in the entry; it should be set to the expected template name for the template.
	Parse(r measurement.FieldReader, pcr uint32, templateHashSize int, templateName []byte) error
	// Size returns the byte size of the parsed base fields.
	Size() int
	// Clear resets the parsed base fields to their zero values.
	Clear()
}

// ExtraFields is implemented by the template-specific field set.
// Each template (e.g., ima-ng, ima-sig, ima-buf) implements this differently.
// extra fields structure:
// ... | ExtraFieldLen | ExtraField0 | ... | ExtraFieldN |.
type ExtraFields interface {
	// GetFields returns a slice of the parsed template-specific fields,
	// which can be used for template hash recomputation and validation.
	GetFields() []fields.TemplateField
	// Size returns the byte size of the extra fields
	Size() int
	// Parse reads the template-specific fields from the provided FieldReader.
	Parse(r measurement.FieldReader) error
	// Clear resets the parsed extra fields to their zero values.
	Clear()
}

// Template represents a parsed IMA template entry, including both
// the common base fields and the template-specific extra fields.
type Template struct {
	BasicEntry

	// extra holds the template-specific fields, which
	// differ for each template type (e.g., ima-ng, ima-sig).
	extra ExtraFields
	// templateName holds the name of the template (e.g., "ima-ng").
	templateName []byte
	// templateHashAlgo is the hash algorithm
	// used by IMA to compute the template hash.
	templateHashAlgo crypto.IMAHashAlgo
	// fileHashAlgo is the hash algorithm
	// used by IMA to hash file content.
	fileHashAlgo crypto.IMAHashAlgo
	// pcr is the TPM PCR index reserved
	// to IMA to extend template hash measurements.
	pcr uint32
}

// NewTemplate creates a new Template struct with the
// provided extra fields and template configuration.
func NewTemplate(
	pcr uint32,
	templateName []byte,
	templateHashAlgo,
	fileHashAlgo crypto.IMAHashAlgo,
	extra ExtraFields,
) (*Template, error) {
	if err := fields.IsPCRValid(pcr); err != nil {
		return nil, fmt.Errorf("invalid PCR index: %d", pcr)
	}
	if !templateHashAlgo.IsTemplateHashAlgo() {
		return nil, fmt.Errorf("invalid template hash algorithm: %s", templateHashAlgo.String())
	}
	if !fileHashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("invalid file hash algorithm: %s", fileHashAlgo.String())
	}
	return &Template{
		extra:            extra,
		templateHashAlgo: templateHashAlgo,
		templateName:     templateName,
		fileHashAlgo:     fileHashAlgo,
		pcr:              pcr,
	}, nil
}

func (t *Template) IsZeroEntry() bool {
	templateHash := t.BasicEntry.TemplateHash()
	for i := range templateHash {
		if templateHash[i] != 0 {
			return false
		}
	}
	return true
}

// Validate recomputes the template hash from the parsed extra
// fields and compares it to the stored template hash field in the entry.
func (t *Template) Validate() error {
	// cannot validate a zero entry, as it has no
	// meaningful template hash to compare against.
	if t.IsZeroEntry() {
		return nil
	}
	packed, err := fields.PackFields(t.extra.GetFields())
	if err != nil {
		return fmt.Errorf("failed to pack extra fields: %w", err)
	}
	computed, err := t.templateHashAlgo.Write(packed)
	if err != nil {
		return fmt.Errorf("failed to compute template hash: %w", err)
	}
	if subtle.ConstantTimeCompare(computed, t.TemplateHash()) != 1 {
		return fmt.Errorf("template hash mismatch: got %x, want %x", computed, t.TemplateHash())
	}
	return nil
}

// Parse reads the entire template entry (base fields and extra fields) from the provided FieldReader.
// It populates the Base fields and Extra fields of the Template struct with the parsed values.
func (t *Template) Parse(r measurement.FieldReader) error {
	var err error
	if err = t.BasicEntry.Parse(
		r,
		t.pcr,
		t.templateHashAlgo.Size(),
		t.templateName,
	); err != nil {
		return fmt.Errorf("failed to parse base fields: %w", err)
	}
	// all extra Fields have a prefix-length field.
	parsedSize, err := r.ReadLen()
	if err != nil {
		return fmt.Errorf("failed to parse extra fields size: %w", err)
	}
	if err = t.extra.Parse(r); err != nil {
		return fmt.Errorf("failed to parse extra fields: %w", err)
	}
	actualSize := t.extra.Size()
	if int(parsedSize) != actualSize {
		return fmt.Errorf("extra fields size mismatch: got %d, want %d", actualSize, parsedSize)
	}
	return nil
}

// GetExtraFields returns the parsed template-specific fields of
// the entry as a slice of TemplateField interfaces.
func (t *Template) GetExtraFields() []fields.TemplateField {
	return t.extra.GetFields()
}

// Size returns the total byte size of the parsed template entry,
// including both the base fields and the extra fields.
func (t *Template) Size() int {
	return t.BasicEntry.Size() + t.extra.Size()
}

// Clear resets all parsed fields of the template entry to their zero values,
// including both the base fields and the extra fields.
func (t *Template) Clear() {
	t.BasicEntry.Clear()
	t.extra.Clear()
}

// BasicEntry represents the common base structure of all IMA templates,
// which includes the PCR, template hash, and template name fields.
//
// | PCR | templateHash | templateName | ... template-specific fields |.
type BasicEntry struct {
	pcr          uint32
	templateHash []byte
	templateName []byte
}

// PCR returns the parsed PCR index field of the entry.
func (b *BasicEntry) PCR() uint32 {
	return b.pcr
}

// TemplateHash returns the parsed template hash field of the entry.
func (b *BasicEntry) TemplateHash() []byte {
	return b.templateHash
}

// TemplateName returns the parsed template name field of the entry.
func (b *BasicEntry) TemplateName() []byte {
	return b.templateName
}

// Size returns the byte size of the parsed entry fields.
func (b *BasicEntry) Size() int {
	size := measurement.IMAPcrFieldSize
	size += len(b.templateHash)
	size += len(b.templateName) + measurement.IMALenFieldSize
	return size
}

// Clear resets the parsed entry fields to their zero values.
func (b *BasicEntry) Clear() {
	b.pcr = 0
	b.templateHash = nil
	b.templateName = nil
}

// Parse reads the PCR, template hash, and template name fields from the provided FieldReader.
// pcr is used to validate the PCR value in the entry; it should be set to the expected PCR index for the template.
// templateName is used to validate the template name field in the entry; it should be set to the expected template name for the template.
// ParseBase should be called by the template-specific ParseEntry method before parsing any template-specific fields.
func (b *BasicEntry) Parse(r measurement.FieldReader, pcr uint32, hashSize int, templateName []byte) error {
	if err := b.parsePCR(r, pcr); err != nil {
		return fmt.Errorf("failed to parse PCR: %w", err)
	}
	if err := b.parseTemplateHash(r, hashSize); err != nil {
		return fmt.Errorf("failed to parse template hash: %w", err)
	}
	if err := b.parseTemplateName(r, templateName); err != nil {
		return fmt.Errorf("failed to parse template name: %w", err)
	}
	return nil
}

// parsePCR reads the PCR field from the provided FieldReader and validates
// it against the expected pcr value before storing it.
func (b *BasicEntry) parsePCR(r measurement.FieldReader, expected uint32) error {
	buf, err := r.ReadFixed(measurement.IMAPcrFieldSize)
	if err != nil {
		return fmt.Errorf("failed to read PCR field: %w", err)
	}
	pcr := binary.LittleEndian.Uint32(buf)
	if pcr != expected {
		return fmt.Errorf("invalid PCR value: got %d, want %d", pcr, expected)
	}
	b.pcr = pcr
	return nil
}

// parseTemplateHash reads the template hash field from the provided FieldReader and stores it in the BasicEntry.
func (b *BasicEntry) parseTemplateHash(r measurement.FieldReader, hashSize int) error {
	buf, err := r.ReadFixed(hashSize)
	if err != nil {
		return fmt.Errorf("failed to read template hash field: %w", err)
	}
	if len(buf) != hashSize {
		return fmt.Errorf("invalid template hash length: got %d, want %d", len(buf), hashSize)
	}
	b.templateHash = bytes.Clone(buf)
	return nil
}

// parseTemplateName reads the template name field from the provided FieldReader and validates it against the expected templateName value
// before storing it in the BasicEntry.
func (b *BasicEntry) parseTemplateName(r measurement.FieldReader, expected []byte) error {
	buf, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read template name field: %w", err)
	}
	if !bytes.Equal(buf, expected) {
		return fmt.Errorf("unexpected template name: got %s, want %s", buf, expected)
	}
	b.templateName = bytes.Clone(buf)
	return nil
}
