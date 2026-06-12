package attestation

import (
	"crypto/subtle"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/crypto"
	"github.com/franc-zar/go-ima/pkg/fields"
)

// Attester tracks the cumulative PCR aggregate and byte offset for incremental
// IMA measurement list verification. All fields are unexported — callers must
// use the provided methods to avoid corrupting internal state.
type Attester struct {
	attested         int64              // absolute byte offset of the last successfully attested position
	aggregate        []byte             // running PCR aggregate (hash-extend chain)
	pcr              uint32             // PCR index reserved for IMA aggregate extensions
	templateHashAlgo crypto.IMAHashAlgo // hash algo used for PCR extends and template hash computation
	fileHashAlgo     crypto.IMAHashAlgo // hash algo used for per-file digest computation
}

// NewAttester constructs a new Attester instance.
func NewAttester(
	pcrIndex uint32,
	templateHashAlgo,
	fileHashAlgo crypto.IMAHashAlgo,
	attested int64,
) (*Attester, error) {
	if err := fields.IsPCRValid(pcrIndex); err != nil {
		return nil, fmt.Errorf("invalid PCR index: %w", err)
	}
	if attested < 0 {
		return nil, fmt.Errorf("invalid attested offset %d: must be non-negative", attested)
	}
	if !templateHashAlgo.IsTemplateHashAlgo() {
		return nil, fmt.Errorf("unsupported template hash algorithm: %v", templateHashAlgo)
	}
	if !fileHashAlgo.IsFileHashAlgo() {
		return nil, fmt.Errorf("unsupported file hash algorithm: %v", fileHashAlgo)
	}

	return &Attester{
		attested:         attested,
		aggregate:        make([]byte, templateHashAlgo.Size()),
		pcr:              pcrIndex,
		templateHashAlgo: templateHashAlgo,
		fileHashAlgo:     fileHashAlgo,
	}, nil
}

func (a *Attester) Attested() int64 {
	return a.attested
}

func (a *Attester) Aggregate() []byte {
	return a.aggregate
}

func (a *Attester) PCR() uint32 {
	return a.pcr
}

func (a *Attester) TemplateHashAlgo() crypto.IMAHashAlgo {
	return a.templateHashAlgo
}

func (a *Attester) FileHashAlgo() crypto.IMAHashAlgo {
	return a.fileHashAlgo
}

// Extend performs a PCR-style hash extension: aggregate = hash(aggregate || templateHash).
func (a *Attester) Extend(templateHash []byte) error {
	aggregate, err := a.templateHashAlgo.Extend(a.aggregate, templateHash)
	if err != nil {
		return fmt.Errorf("failed to extend aggregate: %w", err)
	}
	a.aggregate = aggregate
	return nil
}

// Check returns nil if the current aggregate matches expected.
func (a *Attester) Check(expected []byte) error {
	if subtle.ConstantTimeCompare(a.aggregate, expected) != 1 {
		return fmt.Errorf("aggregate mismatch: computed %x, expected %x", a.aggregate, expected)
	}
	return nil
}

// MarkAttested records pos as the byte position up to which
// the measurement list has been successfully verified.
func (a *Attester) MarkAttested(pos int64) {
	a.attested = pos
}
