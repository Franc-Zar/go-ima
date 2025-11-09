package validator

import (
	"fmt"
	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/templates"
	"github.com/franc-zar/go-ima/pkg/templates/custom"
	"github.com/franc-zar/go-ima/pkg/templates/standard"
	"github.com/modern-go/reflect2"
)

type Validator struct {
	MeasurementList *measurement.List
	Entry           templates.Template
	Integrity       *attestation.Integrity
	Target          attestation.Target
}

func NewValidator(measurementList *measurement.List, entry templates.Template, integrity *attestation.Integrity, target attestation.Target) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           entry,
		Integrity:       integrity,
		Target:          target,
	}
}

func NewCgPathValidator(measurementList *measurement.List, integrity *attestation.Integrity, target *custom.CgPathTarget) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &custom.CgPathTemplate{},
		Integrity:       integrity,
		Target:          target,
	}
}

func NewNgValidator(measurementList *measurement.List, integrity *attestation.Integrity, target *standard.NgTarget) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &standard.NgTemplate{},
		Integrity:       integrity,
		Target:          target,
	}
}

func (v *Validator) ValidateTemplateFields(expected int) error {
	err := v.Entry.ValidateFieldsLen(expected)
	if err != nil {
		return fmt.Errorf("failed to validate template fields: %v", err)
	}
	return nil
}

func (v *Validator) SetAttestationOffset() error {
	err := v.MeasurementList.SetOffset(v.Integrity.GetAttested())
	if err != nil {
		return fmt.Errorf("failed to set attestation offset in measurement list: %v", err)
	}
	return nil
}

func (v *Validator) MeasurementListTPMAttestation() error {
	if !v.Integrity.TPM.IsOpen() {
		return fmt.Errorf("TPM is not open")
	}
	// read PCR value from TPM
	pcrs, err := v.Integrity.TPM.ReadPCRs([]int{int(v.Integrity.GetPCRIndex())}, v.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to read PCR from TPM: %v", err)
	}
	expected := pcrs[v.Integrity.GetPCRIndex()]
	return v.MeasurementListAttestation(expected)
}

func (v *Validator) MeasurementListAttestation(expected []byte) error {
	if len(expected) != v.Integrity.TemplateHashSize() {
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
			return fmt.Errorf("IMA measurement list invalid: computed aggregate: %x does not match expected: %x", v.Integrity.GetAggregate(), expected)
		}

		err = v.Entry.ParseEntry(v.MeasurementList, v.Integrity.GetPCRIndex(), v.Integrity.TemplateHashSize(), v.Integrity.FileHashSize())
		if err != nil {
			return fmt.Errorf("IMA measurement list attestation failed: %v", err)
		}

		if !reflect2.IsNil(v.Target) {
			_, err = v.Target.CheckMatch(v.Entry)
			if err != nil {
				return fmt.Errorf("IMA measurement list attestation failed: %v", err)
			}
		}

		err = v.Integrity.Extend(v.Entry.GetTemplateHash())
		if err != nil {
			return fmt.Errorf("IMA measurement list attestation failed: %v", err)
		}
		err = v.Integrity.Check(expected)
		if err == nil {
			v.Integrity.IncrementAttested(v.MeasurementList.GetPtr())
			return nil
		}
	}
}
