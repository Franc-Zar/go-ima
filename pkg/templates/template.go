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
	ParsePCR(r measurement.FieldReader, reservedPcr uint32) error
	ParseTemplateHash(r measurement.FieldReader, hashSize int) error
	ParseTemplateName(r measurement.FieldReader) error
	ParseExtraFieldsLen(r measurement.FieldReader) (uint32, error)
	ParseExtraFields(r measurement.FieldReader, fileHashSize int) error // ParseFields parses template-specific fields (this is where formats differ)
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

func (b *BasicEntry) Size() int {
	size := utils.PcrSize
	size += len(b.TemplateHash)
	size += len(b.TemplateName) + utils.LenFieldSize
	return size
}

func (b *BasicEntry) ParsePCR(buf []byte, reservedPcr uint32) error {
	bufSize := len(buf)

	if bufSize != utils.PcrSize {
		return fmt.Errorf("invalid entry buffer size: got %d, want %d", bufSize, utils.PcrSize)
	}
	pcr := binary.LittleEndian.Uint32(buf)
	if pcr != reservedPcr {
		return fmt.Errorf("invalid PCR value: got %d, want %d", pcr, reservedPcr)
	}
	b.PCR = pcr
	return nil
}

func (b *BasicEntry) ParseTemplateHash(buf []byte, hashSize int) error {
	bufSize := len(buf)

	if bufSize != hashSize {
		return fmt.Errorf("invalid template hash size: got %d, want %d", bufSize, hashSize)
	}

	b.TemplateHash = make([]byte, hashSize)
	copy(b.TemplateHash, buf)
	return nil
}

func (b *BasicEntry) ParseTemplateName(buf []byte, nameLen uint32, expected []byte) error {
	bufSize := len(buf)
	if uint32(bufSize) != nameLen {
		return fmt.Errorf("invalid template name size: got %d, want %d", bufSize, nameLen)
	}
	nameField := make([]byte, nameLen)
	copy(nameField, buf)
	if bytes.Compare(nameField, expected) != 0 {
		return fmt.Errorf("unexpected template name: got %s, want %s", nameField, expected)
	}
	b.TemplateName = nameField
	return nil
}
