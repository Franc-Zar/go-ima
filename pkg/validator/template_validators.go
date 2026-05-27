package validator

import (
	"github.com/franc-zar/go-ima/pkg/attestation"
	"github.com/franc-zar/go-ima/pkg/measurement"
	"github.com/franc-zar/go-ima/pkg/templates"
	"github.com/franc-zar/go-ima/pkg/templates/custom"
	"github.com/franc-zar/go-ima/pkg/templates/standard"
)

func NewValidator(measurementList *measurement.List, entry templates.Template, integrity *attestation.Attester, target attestation.Target) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           entry,
		Attester:        integrity,
		Target:          target,
	}
}

func NewCgPathValidator(measurementList *measurement.List, integrity *attestation.Attester, target attestation.Target) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &custom.CgPathTemplate{},
		Attester:        integrity,
		Target:          target,
	}
}

func NewNgValidator(measurementList *measurement.List, integrity *attestation.Attester, target attestation.Target) *Validator {
	return &Validator{
		MeasurementList: measurementList,
		Entry:           &standard.NgTemplate{},
		Attester:        integrity,
		Target:          target,
	}
}
