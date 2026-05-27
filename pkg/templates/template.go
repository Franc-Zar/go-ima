package templates

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/utils"
)

const BasicEntryLenFields = 1 // number of length fields in BasicEntry

// Template is the minimal interface every IMA template must implement.
type Template interface {
	ParseEntry(r measurement.FieldReader, reservedPcr uint32, templateHashSize, fileHashSize int) error
	Size() int
	ValidateFieldsLen(expected int) error
	ValidateEntry(templateHashAlgo crypto.Hash) error
	GetTemplateHash() []byte
	Clear()
	Name() []byte
}

type BasicEntry struct {
	PCR          uint32
	TemplateHash []byte
	TemplateName []byte
}

// Size returns the byte size of the parsed entry fields.
// Only meaningful after parsing; returns incorrect values on a zero-value BasicEntry.
func (b *BasicEntry) Size() int {
	size := utils.PcrSize
	size += len(b.TemplateHash)
	size += len(b.TemplateName) + utils.LenFieldSize
	return size
}

func (b *BasicEntry) ParsePCR(buf []byte, reservedPcr uint32) error {
	pcr := binary.LittleEndian.Uint32(buf)
	if pcr != reservedPcr {
		return fmt.Errorf("invalid PCR value: got %d, want %d", pcr, reservedPcr)
	}
	b.PCR = pcr
	return nil
}

func (b *BasicEntry) ParseTemplateHash(buf []byte, hashSize int) error {
	b.TemplateHash = bytes.Clone(buf)
	return nil
}

func (b *BasicEntry) ParseTemplateName(buf []byte, nameLen uint32, expected []byte) error {
	if !bytes.Equal(buf, expected) {
		return fmt.Errorf("unexpected template name: got %s, want %s", buf, expected)
	}
	b.TemplateName = bytes.Clone(buf)
	return nil
}
