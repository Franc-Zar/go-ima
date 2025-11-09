package measurement

import (
	"fmt"
	"github.com/franc-zar/go-ima/pkg/utils"
	"io"
	"os"
)

const DefaultBinaryPath = "/sys/kernel/security/integrity/ima/binary_runtime_measurements"

type ListType uint8

const (
	File ListType = iota
	Raw
)

type FieldReader interface {
	ReadLenValue() ([]byte, error)      // reads <len><value>, returns <value>
	ReadLen() (uint32, error)           // reads an independent <len> field
	ReadFixed(size int) ([]byte, error) // reads direct field
}

type List struct {
	Type ListType // complete path to measurement list file or raw content
	Path string   // path to measurement list file
	file *os.File // file handle to measurement list file
	Raw  []byte   // Raw content of measurement list
	ptr  int64    // ptr contains the number of bytes processed i.e. index of next to read
}

func NewMeasurementListFromRaw(raw []byte, ptr int64) *List {
	return &List{
		Type: Raw,
		Raw:  raw,
		ptr:  ptr,
	}
}

func NewMeasurementListFromFile(path string, ptr int64) *List {
	if path == "" {
		path = DefaultBinaryPath
	}
	return &List{
		Type: File,
		Path: path,
		ptr:  ptr,
	}
}

func (ml *List) ReadLenValue() ([]byte, error) {
	lenField, err := ml.Read(utils.LenFieldSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	fieldLen, err := utils.ParseFieldLen(lenField)
	if err != nil {
		return nil, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	return ml.Read(int(fieldLen))
}

func (ml *List) ReadLen() (uint32, error) {
	lenField, err := ml.Read(utils.LenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	fieldLen, err := utils.ParseFieldLen(lenField)
	if err != nil {
		return 0, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	return fieldLen, nil
}

func (ml *List) ReadFixed(size int) ([]byte, error) {
	return ml.Read(size)
}

func (ml *List) IsRaw() bool {
	return ml.Type == Raw
}

func (ml *List) IsFile() bool {
	return ml.Type == File
}

func (ml *List) IsOpen() bool {
	if !ml.IsFile() {
		return false
	}
	return ml.file != nil
}

func (ml *List) IsReady() bool {
	switch ml.Type {
	case Raw:
		return ml.Raw != nil

	case File:
		return ml.IsOpen()

	default:
		return false
	}
}

func (ml *List) Open(offset int64) error {
	if !ml.IsFile() {
		return fmt.Errorf("invalid IMA measurement list type: %v", ml.Type)
	}

	if ml.IsOpen() {
		return nil
	}

	f, err := os.Open(ml.Path)
	if err != nil {
		return fmt.Errorf("failed to open IMA measurement list: %v", err)
	}

	_, err = f.Seek(offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to offset in IMA measurement list: %v", err)
	}

	ml.file = f
	return nil
}

func (ml *List) SetOffset(offset int64) error {
	switch ml.Type {
	case Raw:
		mlLen := int64(len(ml.Raw))
		if offset < 0 || offset > mlLen {
			return fmt.Errorf("invalid offset for raw IMA measurement list: %d", offset)
		}
		ml.ptr = offset
		return nil

	case File:
		if ml.file == nil {
			return fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		_, err := ml.file.Seek(offset, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek in IMA measurement list: %v", err)
		}
		ml.ptr = offset
		return nil

	default:
		return fmt.Errorf("failed to set offset in IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

func (ml *List) Close() error {
	if !ml.IsFile() {
		return fmt.Errorf("invalid IMA measurement list type: %v", ml.Type)
	}

	if ml.file == nil {
		return nil
	}

	err := ml.file.Close()
	if err != nil {
		return fmt.Errorf("failed to close IMA measurement list: %v", err)
	}

	ml.file = nil
	return nil
}

func (ml *List) ReadAll() ([]byte, error) {
	switch ml.Type {
	case Raw:
		ml.ptr = int64(len(ml.Raw))
		return ml.Raw, nil

	case File:
		if ml.file == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf, err := io.ReadAll(ml.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %v", err)
		}
		ml.ptr = int64(len(buf))
		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

func (ml *List) HasContent() (bool, error) {
	switch ml.Type {
	case Raw:
		return ml.ptr < int64(len(ml.Raw)), nil
	case File:
		if ml.file == nil {
			return false, nil
		}
		info, err := ml.file.Stat()
		if err != nil {
			return false, fmt.Errorf("failed to stat IMA measurement list: %v", err)
		}
		return ml.ptr < info.Size(), nil
	default:
		return false, fmt.Errorf("invalid IMA measurement list type: %v", ml.Type)
	}
}

func (ml *List) Read(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("failed to read IMA measurement list: cannot read %d", n)
	}

	switch ml.Type {
	case Raw:
		if ml.ptr+int64(n) > int64(len(ml.Raw)) {
			return nil, io.EOF
		}
		buf := ml.Raw[ml.ptr : ml.ptr+int64(n)]
		ml.ptr += int64(n)
		return buf, nil

	case File:
		if ml.file == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf := make([]byte, n)
		_, err := io.ReadAtLeast(ml.file, buf, n)
		if err != nil {
			if err == io.EOF {
				return nil, err
			} else {
				return nil, fmt.Errorf("failed to read IMA measurement list: %v", err)
			}
		}
		ml.ptr += int64(n)
		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

func (ml *List) GetPtr() int64 {
	return ml.ptr
}
