package templates

import (
	"fmt"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/fields"
	"github.com/franc-zar/go-ima/pkg/measurement"
)

// NewNgTemplate creates a new ima-ng template with the provided configuration parameters.
// It initializes the template's extra fields (file hash and file path) based on the provided file hash algorithm.
func NewNgTemplate(templateHashAlgo, fileHashAlgo crypto.IMAHashAlgo, pcr uint32) (*Template, error) {
	ngExtra, err := newNgExtra(fileHashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create ng extra fields: %w", err)
	}
	ng, err := NewTemplate(pcr, []byte("ima-ng"), templateHashAlgo, fileHashAlgo, ngExtra)
	if err != nil {
		return nil, fmt.Errorf("failed to create base Template: %w", err)
	}
	return ng, nil
}

// ngExtra represents the ima-ng extra fields (file hash and file path) of the template.
//
// ima-ng template structure:
// | PCR | templateHash | templateName | ngSize | fileHash (d-ng) | filePath (n-ng) |.
type ngExtra struct {
	// fileHash is a d-ng IMA field, digest representing the measure of the target file.
	fileHash *fields.DigestNg
	// filePath is a n-ng IMA field, path to the measured file.
	filePath *fields.NameNg
}

// newNgExtra creates a new ngExtra struct with initialized
// fields based on the provided file hash algorithm.
func newNgExtra(hashAlgo crypto.IMAHashAlgo) (*ngExtra, error) {
	fileHash, err := fields.NewDigestNg(hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create DigestNg field: %w", err)
	}
	filePath := fields.NewNameNg()

	return &ngExtra{
		fileHash: fileHash,
		filePath: filePath,
	}, nil
}

// GetFields returns the template extra fields
// in the order they are packed in the template.
func (n *ngExtra) GetFields() []fields.TemplateField {
	return []fields.TemplateField{n.fileHash, n.filePath}
}

// Size returns the byte size of the ima-ng specific fields
// (file hash and file path) including their length fields.
func (n *ngExtra) Size() int {
	return n.fileHash.Size() + n.filePath.Size()
}

// Parse reads and parses the ima-ng specific fields
// (file hash and file path) from the provided FieldReader.
func (n *ngExtra) Parse(r measurement.FieldReader) error {
	if err := n.fileHash.Parse(r); err != nil {
		return fmt.Errorf("failed to parse file hash: %w", err)
	}
	if err := n.filePath.Parse(r); err != nil {
		return fmt.Errorf("failed to parse file path: %w", err)
	}
	return nil
}

// Clear resets the parsed file hash and
// file path fields to their zero values.
func (n *ngExtra) Clear() {
	n.fileHash.Clear()
	n.filePath.Clear()
}
