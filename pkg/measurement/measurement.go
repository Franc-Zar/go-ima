package measurement

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultBinaryPath is the default path to the IMA binary measurement list.
const DefaultBinaryPath = "/sys/kernel/security/integrity/ima/binary_runtime_measurements"

// ListType identifies the source backing an IMA measurement list reader.
type ListType uint8

const (
	// File indicates a file-backed measurement list source.
	File ListType = iota
	// Raw indicates an in-memory byte-backed measurement list source.
	Raw
)

// List provides sequential reads over an IMA measurement list.
type List struct {
	Type ListType      // Type of IMA measurement list: file or raw content
	Path string        // path to IMA measurement list file
	file *os.File      // file handle to IMA measurement list file
	Raw  *bytes.Reader // Raw content of IMA measurement list
	ptr  int64         // ptr contains the number of bytes processed i.e. index of next to read
}

// NewIMAListFromRaw creates a List from raw measurement list bytes.
func NewIMAListFromRaw(raw []byte, ptr int64) *List {
	return &List{
		Type: Raw,
		Raw:  bytes.NewReader(raw),
		ptr:  ptr,
	}
}

// NewIMAListFromFile creates a file-backed List and opens it at ptr.
func NewIMAListFromFile(path string, ptr int64) (*List, error) {
	if path == "" {
		path = DefaultBinaryPath
	}

	l := &List{
		Type: File,
		Path: path,
		ptr:  ptr,
	}
	err := l.Open(ptr)
	if err != nil {
		return nil, fmt.Errorf("failed to create List from file: %w", err)
	}

	return l, nil
}

// ReadLenValue reads a <len><value> field and returns only the value bytes.
func (il *List) ReadLenValue() ([]byte, error) {
	fieldLen, err := il.ReadLen()
	if err != nil {
		return nil, err
	}
	if fieldLen == 0 {
		return []byte{}, nil
	}
	return il.Read(int(fieldLen))
}

// ReadLen reads and parses a 4-byte little-endian length field.
func (il *List) ReadLen() (uint32, error) {
	lenField, err := il.Read(IMALenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read length field from IMA measurement list: %w", err)
	}
	fieldLen, err := ParseFieldLen(lenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse length field from IMA measurement list: %w", err)
	}
	return fieldLen, nil
}

// ReadFixed reads exactly size bytes from the current reader position.
func (il *List) ReadFixed(size int) ([]byte, error) {
	return il.Read(size)
}

// Helper: get total size for both types.
func (il *List) totalSize() (int64, error) {
	switch il.Type {
	case Raw:
		if il.Raw == nil {
			return 0, errors.New("raw data not available")
		}
		return il.Raw.Size(), nil
	case File:
		if il.file == nil {
			return 0, errors.New("file is not open")
		}
		info, err := il.file.Stat()
		if err != nil {
			return 0, fmt.Errorf("stat error: %w", err)
		}
		return info.Size(), nil
	default:
		return 0, fmt.Errorf("unknown measurement list type: %v", il.Type)
	}
}

// IsReady reports whether the underlying source is initialized and readable.
func (il *List) IsReady() bool {
	switch il.Type {
	case Raw:
		return il.Raw != nil
	case File:
		return il.file != nil
	default:
		return false
	}
}

// Open opens the file-backed source and seeks to pos.
// For raw sources, Open is a no-op.
func (il *List) Open(pos int64) error {
	if il.Type != File {
		return nil
	}

	if il.file != nil {
		return nil
	}

	f, err := os.Open(il.Path)
	if err != nil {
		return fmt.Errorf("failed to open IMA measurement list: %w", err)
	}

	if _, err = f.Seek(pos, io.SeekStart); err != nil {
		cErr := f.Close()
		if cErr != nil {
			return fmt.Errorf("seek error: %w, close error: %w", err, cErr)
		}
		return fmt.Errorf("seek error: %w", err)
	}

	il.file = f
	il.ptr = pos
	return nil
}

// SetPosition moves the current read position to pos.
func (il *List) SetPosition(pos int64) error {
	switch il.Type {
	case Raw:
		if il.Raw == nil {
			return errors.New("raw data not available")
		}
		if _, err := il.Raw.Seek(pos, io.SeekStart); err != nil {
			return fmt.Errorf("seek error: %w", err)
		}
		il.ptr = pos
		return nil
	case File:
		if il.file == nil {
			return errors.New("file is not open")
		}
		if _, err := il.file.Seek(pos, io.SeekStart); err != nil {
			return fmt.Errorf("seek error: %w", err)
		}
		il.ptr = pos
		return nil
	default:
		return fmt.Errorf("unknown measurement list type: %v", il.Type)
	}
}

// Close closes the file-backed source.
// For raw sources, Close is a no-op.
func (il *List) Close() error {
	if il.Type == Raw || il.file == nil {
		return nil
	}
	if err := il.file.Close(); err != nil {
		return fmt.Errorf("close error: %w", err)
	}
	il.file = nil
	return nil
}

// ReadAll reads remaining bytes from the current position.
func (il *List) ReadAll() ([]byte, error) {
	switch il.Type {
	case Raw:
		buf, err := io.ReadAll(il.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %w", err)
		}
		il.ptr += int64(len(buf))
		return buf, nil

	case File:
		if il.file == nil {
			return nil, errors.New("failed to read IMA measurement list: file is not open")
		}

		buf, err := io.ReadAll(il.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %w", err)
		}
		il.ptr += int64(len(buf))
		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", il.Type)
	}
}

// Remaining reports whether unread content is available.
func (il *List) Remaining() (bool, error) {
	size, err := il.totalSize()
	if err != nil {
		return false, err
	}
	return il.ptr < size, nil
}

// Read reads n bytes and advances the current read position.
func (il *List) Read(n int) ([]byte, error) {
	if n < 1 {
		return nil, fmt.Errorf("failed to read IMA measurement list: cannot read %d bytes", n)
	}
	switch il.Type {
	case Raw:
		if il.Raw == nil {
			return nil, errors.New("failed to read IMA measurement list: data not available")
		}
		buf := make([]byte, n)
		_, err := il.Raw.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %w", err)
		}
		il.ptr += int64(n)
		return buf, nil

	case File:
		if il.file == nil {
			return nil, errors.New("failed to read IMA measurement list: file is not open")
		}

		buf := make([]byte, n)
		_, err := io.ReadFull(il.file, buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %w", err)
		}
		il.ptr += int64(n)
		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", il.Type)
	}
}

// GetPtr returns the current absolute read offset.
func (il *List) GetPtr() int64 {
	return il.ptr
}
