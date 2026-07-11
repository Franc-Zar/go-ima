package fields

import (
	"bytes"

	"encoding/binary"
	"errors"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/measurement"
)

// Unpad removes the padding bytes from the provided buffer
// and returns the unpadded content.
// It returns an error if the padding is invalid.
func Unpad(buf []byte, padding byte) ([]byte, error) {
	start, err := ValidatePadding(buf, padding)
	if err != nil {
		return nil, err
	}
	return buf[:start], nil
}

// PackFields packs the provided fields according to
// provided order and returns the packed byte slice.
func PackFields(fields []TemplateField) ([]byte, error) {
	packed := new(bytes.Buffer)
	for _, field := range fields {
		packedField, err := field.Pack()
		if err != nil {
			return nil, fmt.Errorf("failed to pack field %s: %w", field.ID(), err)
		}
		packed.Write(packedField)
	}
	return packed.Bytes(), nil
}

// PackRaw packs the provided raw byte slice by prepending its length as a 4-byte little-endian uint32.
// It returns an error if the length of the byte slice exceeds the maximum allowed size.
func PackRaw(b []byte) ([]byte, error) {
	bufLen := len(b)
	//nolint:mnd // maximum length of a buffer to pack is 2^32-1 bytes (uint32)
	if bufLen > (1<<(measurement.IMALenFieldSize*8))-1 {
		return nil, fmt.Errorf("buffer too large to pack: size %d exceeds maximum allowed", bufLen)
	}
	packed := new(bytes.Buffer)
	if err := binary.Write(packed, binary.LittleEndian, uint32(bufLen)); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %w", err)
	}
	n, err := packed.Write(b)
	if err != nil {
		return nil, fmt.Errorf("failed to pack raw data: %w", err)
	}
	if n != bufLen {
		return nil, fmt.Errorf("failed to pack complete raw data: wrote %d, want %d", n, bufLen)
	}
	return packed.Bytes(), nil
}

// ValidatePadding checks that all bytes in the provided buffer after the first
// occurrence of the specified padding byte are equal to the padding byte.
// It returns the start index of the padding (which is the unpadded buffer content length)
// and an error if the padding is invalid.
func ValidatePadding(buf []byte, padding byte) (int, error) {
	padStart := -1
	for i := range buf {
		if buf[i] == padding {
			padStart = i
			break
		}
	}
	if padStart == -1 {
		return -1, errors.New("padding byte not found in buffer")
	}

	for i := padStart; i < len(buf); i++ {
		if buf[i] != padding {
			return padStart, errors.New("invalid padding")
		}
	}
	return padStart, nil
}

// IsPCRValid validates that pcrIndex is within the supported TPM PCR range.
func IsPCRValid(pcrIndex uint32) error {
	if pcrIndex < MinPCRIndex || pcrIndex > MaxPCRIndex {
		return fmt.Errorf("PCR index must be between %d and %d", MinPCRIndex, MaxPCRIndex)
	}
	return nil
}

// ValidateFileHash validates and extracts the digest from a d-ng field payload.
func ValidateFileHash(fileHash []byte, hashAlgo crypto.IMAHashAlgo) ([]byte, error) {
	// fileHash structure is <algoDescriptor>:<NULL_BYTE><digest>
	if !hashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("provided hash algorithm is not valid for file hash: %s", hashAlgo.String())
	}

	algoDescriptor, digest, found := bytes.Cut(fileHash, []byte{measurement.ColonByte})
	if !found {
		return nil, errors.New("invalid file hash format: missing ':' separator")
	}

	if string(algoDescriptor) != hashAlgo.String() {
		return nil, fmt.Errorf("invalid file hash algorithm: got %s, want %s", algoDescriptor, hashAlgo.String())
	}

	if digest[0] != 0 {
		return nil, errors.New("invalid file hash format: missing NULL byte separator")
	}
	digest = digest[1:]

	digestSize := len(digest)
	if digestSize != hashAlgo.Size() {
		return nil, fmt.Errorf("invalid file hash digest size: got %d, want %d", digestSize, hashAlgo.Size())
	}

	return digest, nil
}

// ValidateFileHashV2 validates and extracts the digest from a d-ngv2 field payload.
func ValidateFileHashV2(fileHash []byte, hashAlgo crypto.IMAHashAlgo, digestType DigestType) ([]byte, error) {
	// fileHash structure is <digestType>:<algoDescriptor>:<NULL_BYTE><digest>
	if !hashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("provided hash algorithm is not valid for file hash: %s", hashAlgo.String())
	}

	parsedType, digest, found := bytes.Cut(fileHash, []byte{measurement.ColonByte})
	if !found {
		return nil, errors.New("invalid file hash format: missing ':' separator")
	}
	if string(parsedType) != digestType.String() {
		return nil, fmt.Errorf("invalid file hash digest type: got %s, want %s", parsedType, digestType.String())
	}

	algoDescriptor, digest, found := bytes.Cut(digest, []byte{measurement.ColonByte})
	if !found {
		return nil, errors.New("invalid file hash format: missing ':' separator")
	}

	if string(algoDescriptor) != hashAlgo.String() {
		return nil, fmt.Errorf("invalid file hash algorithm: got %s, want %s", algoDescriptor, hashAlgo.String())
	}

	digestSize := len(digest)
	if digestSize != hashAlgo.Size() {
		return nil, fmt.Errorf("invalid file hash digest size: got %d, want %d", digestSize, hashAlgo.Size())
	}

	return digest, nil
}

// IsSigVersionValid validates that version is a supported IMA signature version.
func IsSigVersionValid(version uint8) error {
	if version != SigV2 && version != SigV3 {
		return fmt.Errorf("invalid signature header: unsupported version, got 0x%02x, want 0x02 or 0x03", version)
	}
	return nil
}

// ValidateSig validates the IMA sig field and returns an error if any subfield is invalid.
// [magic=0x03][version=0x02][hash_algo uint8][keyid uint32][sigsize uint16][sig bytes[]].
func ValidateSig(rawSig []byte) (byte, crypto.IMAHashAlgo, uint32, []byte, error) {
	if len(rawSig) < SigHeaderSize {
		return 0, crypto.Unsupported, 0, nil, fmt.Errorf(
			"invalid signature header: got %d bytes, want at least %d",
			len(rawSig),
			SigHeaderSize,
		)
	}

	header := rawSig[:SigHeaderSize]

	magic := header[0]
	if magic != IMADigSigType {
		return 0, crypto.Unsupported, 0, nil, fmt.Errorf(
			"invalid signature header: unexpected magic byte, got 0x%02x, want 0x%02x",
			magic,
			IMADigSigType,
		)
	}
	version := header[1]
	if err := IsSigVersionValid(version); err != nil {
		return 0, crypto.Unsupported, 0, nil, fmt.Errorf("invalid signature header: %w", err)
	}
	algoID := header[2]
	hashAlgo := crypto.GetIMASigHashAlgo(algoID)
	if hashAlgo == crypto.Unsupported {
		return 0, crypto.Unsupported, 0, nil, fmt.Errorf(
			"invalid signature header: unsupported hash algorithm ID, got 0x%02x",
			algoID,
		)
	}

	sig := rawSig[SigHeaderSize:]
	sigLen := len(sig)
	sigSize := binary.BigEndian.Uint16(header[7:SigHeaderSize])
	if sigLen != int(sigSize) {
		return 0, crypto.Unsupported, 0, nil, fmt.Errorf(
			"invalid signature header: signature size mismatch, got %d, want %d",
			sigLen,
			sigSize,
		)
	}

	keyID := binary.LittleEndian.Uint32(header[3:7])
	return version, hashAlgo, keyID, sig, nil
}
