package measurement

// FieldReader abstracts reading and seeking over parsed IMA field streams.
type FieldReader interface {
	// ReadLenValue reads a length-prefixed value <len><value> from the underlying data source and returns only the <value>.
	ReadLenValue() ([]byte, error)
	// ReadLen reads an independent length field <len> (i.e., a field that specifies the length of a group of fields) from the underlying data source.
	ReadLen() (uint32, error)
	// ReadFixed reads a fixed-size field of the specified size from the underlying data source.
	ReadFixed(size int) ([]byte, error)
	// GetPtr returns the current read pointer position in the underlying data source.
	GetPtr() int64
	// SetPosition sets the read pointer position in the underlying data source to the specified position.
	SetPosition(pos int64) error
	// IsReady checks if the underlying data source is ready for reading (e.g., opened or initialized).
	IsReady() bool
	// Remaining checks if the underlying data source has any content to read.
	Remaining() (bool, error)
}
