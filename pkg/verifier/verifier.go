package verifier

import (
	"errors"
	"fmt"

	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/templates"
)

// Verifier ties together a measurement list source, a template parser, an
// attestation state tracker, and an optional match target. All fields are
// unexported so callers go through the provided methods.
type Verifier struct {
	measurementList measurement.FieldReader
	entry           *templates.Template
	attester        *attestation.Attester
}

// NewVerifier constructs a Verifier with an explicit template implementation.
// Use this when you have a custom or future template type.
func NewVerifier(
	measurementList measurement.FieldReader,
	entry *templates.Template,
	attester *attestation.Attester,
) *Verifier {
	return &Verifier{
		measurementList: measurementList,
		entry:           entry,
		attester:        attester,
	}
}

// MeasurementList returns the underlying measurement list for inspection.
func (v *Verifier) MeasurementList() measurement.FieldReader {
	return v.measurementList
}

// Attester returns the attestation state tracker.
func (v *Verifier) Attester() *attestation.Attester {
	return v.attester
}

// SetAttestationPosition seeks the measurement list to the last successfully
// attested byte position recorded in the attester.
func (v *Verifier) SetAttestationPosition() error {
	err := v.measurementList.SetPosition(v.attester.Attested())
	if err != nil {
		return fmt.Errorf("failed to seek measurement list to attested position: %w", err)
	}
	return nil
}

// MeasurementListAttestation replays the measurement list from the current
// attested position, extending the PCR aggregate entry by entry, until the
// aggregate matches expected or the list is exhausted.
//
// The loop-until-match strategy is intentional: the PCR value from a TPM
// quote may have been extended by one or a few entries after the measurement
// list snapshot was taken, so the match point may be slightly before EOF.
// On a successful match, the attested position is updated to the current
// read position so the next call resumes from there.
func (v *Verifier) MeasurementListAttestation(expected []byte) error {
	if len(expected) != v.attester.TemplateHashAlgo().Size() {
		return fmt.Errorf("expected aggregate length %d does not match template hash size %d",
			len(expected), v.attester.TemplateHashAlgo().Size())
	}

	if !v.measurementList.IsReady() {
		return errors.New("measurement list is not ready (not opened or no data)")
	}

	for {
		hasContent, err := v.measurementList.Remaining()
		if err != nil {
			return fmt.Errorf("failed to check measurement list content: %w", err)
		}
		if !hasContent {
			// Exhausted the log without finding a match — the expected value
			// is either wrong or the log is missing entries.
			return errors.New("measurement list exhausted without matching expected aggregate")
		}

		v.entry.Clear()

		err = v.entry.Parse(v.measurementList)
		if err != nil {
			return fmt.Errorf("failed to parse entry: %w", err)
		}

		err = v.entry.Validate()
		if err != nil {
			return fmt.Errorf("failed to validate entry integrity: %w", err)
		}

		if err = v.attester.Extend(v.entry.TemplateHash()); err != nil {
			return fmt.Errorf("failed to extend PCR aggregate: %w", err)
		}

		if err = v.attester.Check(expected); err == nil {
			// Aggregate matches: record the current absolute read position
			// as the new attested position and return success.
			v.attester.MarkAttested(v.measurementList.GetPtr())
			return nil
		}
		// Aggregate does not match yet — consume more entries.
	}
}
