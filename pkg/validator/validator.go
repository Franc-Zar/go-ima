package validator

import (
	"fmt"

	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/templates"
)

type Validator struct {
	MeasurementList *measurement.List
	Entry           templates.Template
	Attester        *attestation.Attester
	Target          attestation.Target
}

func (v *Validator) ValidateTemplateFields(expected int) error {
	err := v.Entry.ValidateFieldsLen(expected)
	if err != nil {
		return fmt.Errorf("failed to validate template fields: %v", err)
	}
	return nil
}

func (v *Validator) SetAttestationOffset() error {
	err := v.MeasurementList.SetOffset(v.Attester.GetAttested())
	if err != nil {
		return fmt.Errorf("failed to set attestation offset in measurement list: %v", err)
	}
	return nil
}

func (v *Validator) MeasurementListAttestation(expected []byte) error {
	if len(expected) != v.Attester.TemplateHashSize() {
		return fmt.Errorf("expected aggregate size does not match template hash size")
	}

	if !v.MeasurementList.IsReady() {
		return fmt.Errorf("IMA measurement list is not ready for attestation")
	}

	var err error
	var hasContent bool
	// process measurement list entries until EOF
	for {
		v.Entry.Clear()

		hasContent, err = v.MeasurementList.HasContent()
		if err != nil {
			return fmt.Errorf("IMA measurement list attestation failed: %v", err)
		}

		if !hasContent {
			return fmt.Errorf("IMA measurement list invalid: aggregate does not match expected value")
		}

		err = v.Entry.ParseEntry(v.MeasurementList, v.Attester.GetPCRIndex(), v.Attester.TemplateHashSize(), v.Attester.FileHashSize())
		if err != nil {
			return fmt.Errorf("IMA measurement list attestation failed: %v", err)
		}

		if v.Target != nil {
			_, err = v.Target.CheckMatch(v.Entry)
			if err != nil {
				return fmt.Errorf("IMA measurement list attestation failed: %v", err)
			}
		}

		err = v.Attester.Extend(v.Entry.GetTemplateHash())
		if err != nil {
			return fmt.Errorf("IMA measurement list attestation failed: %v", err)
		}
		err = v.Attester.Check(expected)
		if err == nil {
			v.Attester.IncrementAttested(v.MeasurementList.GetPtr())
			return nil
		}
	}
}
