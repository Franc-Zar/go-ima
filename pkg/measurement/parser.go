package measurement

import (
	"encoding/binary"
	"fmt"
)

const (
	// ColonByte is the ':' separator used in encoded IMA field payloads.
	ColonByte = byte(58)
	// NullByte is the NUL terminator used by multiple IMA string fields.
	NullByte = byte(0)
	// IMALenFieldSize IMA length fields size in bytes (uint32).
	IMALenFieldSize = 4
	// IMAPcrFieldSize IMA PCR fields size in bytes (uint32).
	IMAPcrFieldSize = 4
)

// ParseFieldLen parses a length field from a byte buffer and returns the length as uint32.
func ParseFieldLen(field []byte) (uint32, error) {
	fieldSize := len(field)
	if fieldSize != IMALenFieldSize {
		return 0, fmt.Errorf("invalid length field size: got %d, want %d", fieldSize, IMALenFieldSize)
	}
	fieldLen := binary.LittleEndian.Uint32(field)
	return fieldLen, nil
}
