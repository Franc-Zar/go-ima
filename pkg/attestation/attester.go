package attestation

import (
	"crypto"
	"crypto/subtle"
	"fmt"
)

const (
	MinPCRIndex     = 0
	MaxPCRIndex     = 23
	DefaultPCRIndex = 10
)

type Attester struct {
	attested  int64  // number of attested bytes of IMA measurement list bytes i.e. starting offset for next measurement list verification
	aggregate []byte // cumulative hash of processed IMA measurements
	pcrIndex  uint32 // index of PCR reserved to store IMA measurements

	TemplateHashAlgo crypto.Hash // hash algorithm used for template hash computation
	FileHashAlgo     crypto.Hash // hash algorithm used for file hash computation
}

func (a *Attester) GetAttested() int64 {
	return a.attested
}

func (a *Attester) GetAggregate() []byte {
	return a.aggregate
}

func (a *Attester) GetPCRIndex() uint32 {
	return a.pcrIndex
}

func NewAttester(pcrIndex uint32, templateHashAlgo, fileHashAlgo crypto.Hash, attested int64) (*Attester, error) {
	a := &Attester{
		attested:         attested,
		aggregate:        make([]byte, templateHashAlgo.Size()),
		pcrIndex:         pcrIndex,
		TemplateHashAlgo: templateHashAlgo,
		FileHashAlgo:     fileHashAlgo,
	}
	if !a.isPCRHashAlgo() {
		return nil, fmt.Errorf("invalid template hash algorithm configuration: %v", templateHashAlgo)
	}
	if !a.isFileHashAlgo() {
		return nil, fmt.Errorf("invalid file hash algorithm configuration: %v", fileHashAlgo)
	}
	if !a.IsValidPCRIndex() {
		return nil, fmt.Errorf("invalid PCR index for IMA measurements: %d", pcrIndex)
	}
	return a, nil
}

func (a *Attester) isFileHashAlgo() bool {
	switch a.FileHashAlgo {
	case crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func (a *Attester) IsValidPCRIndex() bool {
	return a.pcrIndex >= MinPCRIndex && a.pcrIndex <= MaxPCRIndex
}

func (a *Attester) IsValidHashConfig() bool {
	return a.isPCRHashAlgo() && a.isFileHashAlgo()
}

func (a *Attester) TemplateHashSize() int {
	return a.TemplateHashAlgo.Size()
}

func (a *Attester) FileHashSize() int {
	return a.FileHashAlgo.Size()
}

func (a *Attester) Extend(templateHash []byte) error {
	hash := a.TemplateHashAlgo.New()

	toExtend := append(a.aggregate, templateHash...)
	toHashLen := len(toExtend)
	n, err := hash.Write(toExtend)
	if n != toHashLen {
		return fmt.Errorf("failed to write data to hash buffer: wrote only %d < %d bytes", n, toHashLen)
	}
	if err != nil {
		return fmt.Errorf("failed to write data to hash buffer: %v", err)
	}

	a.aggregate = hash.Sum(nil)
	return nil
}

func (a *Attester) Check(expectedAggregate []byte) error {
	if subtle.ConstantTimeCompare(a.aggregate, expectedAggregate) != 1 {
		return fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match expected value")
	}
	return nil
}

func (a *Attester) IncrementAttested(n int64) {
	a.attested += n
}

func (a *Attester) isPCRHashAlgo() bool {
	switch a.TemplateHashAlgo {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}
