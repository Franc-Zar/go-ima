package crypto

import (
	"crypto"
	//nolint: gosec // ignore the security linter for md5 as it is used for IMA hash algorithms
	_ "crypto/md5"
	//nolint: gosec // ignore the security linter for sha1 as it is used for IMA hash algorithms
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

const (
	// UnsupportedHashAlgoString is returned by String for unknown hash algorithms.
	UnsupportedHashAlgoString = "unsupported IMA hash algorithm"
	md5Str                    = "md5"
	sha1Str                   = "sha1"
	sha256Str                 = "sha256"
	sha384Str                 = "sha384"
	sha512Str                 = "sha512"
	sha224Str                 = "sha224"
)

// IMAHashAlgo identifies hash algorithms supported by IMA helpers.
type IMAHashAlgo uint

const (
	// Unsupported indicates an unknown or unsupported hash algorithm.
	Unsupported IMAHashAlgo = 0
	// MD5 identifies the md5 hash algorithm.
	MD5 IMAHashAlgo = IMAHashAlgo(crypto.MD5)
	// SHA1 identifies the sha1 hash algorithm.
	SHA1 IMAHashAlgo = IMAHashAlgo(crypto.SHA1)
	// SHA224 identifies the sha224 hash algorithm.
	SHA224 IMAHashAlgo = IMAHashAlgo(crypto.SHA224)
	// SHA256 identifies the sha256 hash algorithm.
	SHA256 IMAHashAlgo = IMAHashAlgo(crypto.SHA256)
	// SHA384 identifies the sha384 hash algorithm.
	SHA384 IMAHashAlgo = IMAHashAlgo(crypto.SHA384)
	// SHA512 identifies the sha512 hash algorithm.
	SHA512 IMAHashAlgo = IMAHashAlgo(crypto.SHA512)
)

// imaFileHashNames maps every IMA kernel name (as written in the d-ng field
// and accepted by ima_hash=) to its HashAlgo constant.
var imaFileHashNames = map[string]IMAHashAlgo{
	md5Str:    MD5,
	sha1Str:   SHA1,
	sha224Str: SHA224,
	sha256Str: SHA256,
	sha384Str: SHA384,
	sha512Str: SHA512,
}

// imaTemplateHashNames is the subset valid for template hashing (PCR extend).
// Source: linux/security/integrity/ima/Kconfig.
var imaTemplateHashNames = map[string]IMAHashAlgo{
	sha1Str:   SHA1,
	sha256Str: SHA256,
	sha384Str: SHA384,
	sha512Str: SHA512,
}

// imaHashAlgoToCryptoHash maps every IMA hash algorithm to
// the corresponding [crypto.Hash].
var imaHashAlgoToCryptoHash = map[IMAHashAlgo]crypto.Hash{
	Unsupported: crypto.Hash(0),
	MD5:         crypto.MD5,
	SHA1:        crypto.SHA1,
	SHA224:      crypto.SHA224,
	SHA256:      crypto.SHA256,
	SHA384:      crypto.SHA384,
	SHA512:      crypto.SHA512,
}

// imaSigHashAlgo maps supported IMA signature hash algorithms to
// their kernel mapped identifiers.
var imaSigHashAlgo = map[uint8]IMAHashAlgo{
	2: SHA1,
	4: SHA256,
	7: SHA384,
	8: SHA512,
	// TODO: define SM3
}

var imaSigHashNames = map[string]IMAHashAlgo{
	sha1Str:   SHA1,
	sha256Str: SHA256,
	sha384Str: SHA384,
	sha512Str: SHA512,
}

// GetIMASigHashAlgo returns the IMA signature hash algorithm corresponding to the
// given kernel identifier, or Unsupported if the identifier is not recognized.
func GetIMASigHashAlgo(algoID uint8) IMAHashAlgo {
	if algo, ok := imaSigHashAlgo[algoID]; ok {
		return algo
	}
	return Unsupported
}

// GetIMAFileHashAlgo returns the IMA file hash algorithm corresponding to the
// given kernel name, or Unsupported if the name is not recognized.
func GetIMAFileHashAlgo(name string) IMAHashAlgo {
	if algo, ok := imaFileHashNames[name]; ok {
		return algo
	}
	return Unsupported
}

// GetIMATemplateHashAlgo returns the IMA template hash algorithm corresponding to the
// given kernel name, or Unsupported if the name is not recognized.
func GetIMATemplateHashAlgo(name string) IMAHashAlgo {
	if algo, ok := imaTemplateHashNames[name]; ok {
		return algo
	}
	return Unsupported
}

// IMAHashAlgoFromCryptoHash returns the IMA hash algorithm corresponding to the given
// [crypto.Hash], or Unsupported if the [crypto.Hash] is not recognized.
func IMAHashAlgoFromCryptoHash(h crypto.Hash) IMAHashAlgo {
	for algo, cryptoHash := range imaHashAlgoToCryptoHash {
		if cryptoHash == h {
			return algo
		}
	}
	return Unsupported
}

// ToIMASigHashID returns the kernel identifier corresponding to the given IMA signature hash algorithm,
// or an error if the algorithm is not supported for signature hashing.
func (a IMAHashAlgo) ToIMASigHashID() (uint8, error) {
	for id, algo := range imaSigHashAlgo {
		if algo == a {
			return id, nil
		}
	}
	return 0, fmt.Errorf("unsupported IMA signature hash algorithm: %v", a)
}

// ToCryptoHash returns the [crypto.Hash] corresponding to the given IMA hash algorithm,
// or 0 if the IMA hash algorithm is not recognized.
func (a IMAHashAlgo) ToCryptoHash() crypto.Hash {
	if cryptoHash, ok := imaHashAlgoToCryptoHash[a]; ok {
		return cryptoHash
	}
	return crypto.Hash(0) // invalid crypto hash
}

// String returns the string representation of the IMA hash algorithm,
// or "unsupported IMA hash algorithm" if the algorithm is not recognized.
func (a IMAHashAlgo) String() string {
	for name, algo := range imaFileHashNames {
		if algo == a {
			return name
		}
	}
	for name, algo := range imaTemplateHashNames {
		if algo == a {
			return name
		}
	}
	for name, algo := range imaSigHashNames {
		if algo == a {
			return name
		}
	}
	return UnsupportedHashAlgoString
}

// Size returns the size in bytes of the hash output for the
// IMA hash algorithm, or -1 if the algorithm is not recognized or unsupported.
func (a IMAHashAlgo) Size() int {
	if cryptoHash, ok := imaHashAlgoToCryptoHash[a]; ok {
		return cryptoHash.Size()
	}
	// unsupported crypto hash
	return -1
}

// IsFileHashAlgo returns true if the IMA hash algorithm is supported
// for file hashing.
func (a IMAHashAlgo) IsFileHashAlgo() bool {
	_, ok := imaFileHashNames[a.String()]
	return ok
}

// IsTemplateHashAlgo returns true if the IMA hash algorithm is supported
// for template hashing (PCR extend).
func (a IMAHashAlgo) IsTemplateHashAlgo() bool {
	_, ok := imaTemplateHashNames[a.String()]
	return ok
}

// IsSigAlgo reports whether a is valid in IMA signature headers.
func (a IMAHashAlgo) IsSigAlgo() bool {
	_, ok := imaSigHashNames[a.String()]
	return ok
}

// Extend computes the new aggregate hash by extending the current aggregate with the given template hash.
// The aggregate is the cumulative hash of all previous events, and the templateHash is the hash of the current event.
// It is used to perform event replay to verify that the same aggregate digest is
// obtained by replaying the same sequence of events: hash(aggregate || templateHash).
//
// It returns an error if the IMA hash algorithm is not supported for template hashing or if the underlying crypto hash algorithm is not recognized.
func (a IMAHashAlgo) Extend(aggregate, templateHash []byte) ([]byte, error) {
	if !a.IsTemplateHashAlgo() {
		return nil, fmt.Errorf("unsupported IMA template hash algorithm: %v", a)
	}
	cryptoHash := a.ToCryptoHash()
	if cryptoHash == 0 {
		return nil, fmt.Errorf("unsupported IMA hash algorithm: %v", a)
	}
	h := cryptoHash.New()
	aggregate = append(aggregate, templateHash...)
	n, err := h.Write(aggregate)
	if err != nil {
		return nil, fmt.Errorf("failed to write to hash: %w", err)
	}
	if n != len(aggregate) {
		return nil, fmt.Errorf("incomplete write to hash: %d of %d bytes", n, len(aggregate))
	}

	return h.Sum(nil), nil
}

// Write hashes data with the selected algorithm and returns the digest.
func (a IMAHashAlgo) Write(data []byte) ([]byte, error) {
	cryptoHash := a.ToCryptoHash()
	if cryptoHash == 0 {
		return nil, fmt.Errorf("unsupported IMA hash algorithm: %v", a)
	}
	h := cryptoHash.New()
	n, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write to hash: %w", err)
	}
	if n != len(data) {
		return nil, fmt.Errorf("incomplete write to hash: %d of %d bytes", n, len(data))
	}
	return h.Sum(nil), nil
}
