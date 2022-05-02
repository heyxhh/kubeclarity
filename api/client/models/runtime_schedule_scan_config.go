// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RuntimeScheduleScanConfig runtime schedule scan config
//
// swagger:model RuntimeScheduleScanConfig
type RuntimeScheduleScanConfig struct {

	// cis docker benchmark scan enabled
	CisDockerBenchmarkScanEnabled bool `json:"cisDockerBenchmarkScanEnabled,omitempty"`

	// namespaces
	Namespaces []string `json:"namespaces"`

	scanConfigTypeField RuntimeScheduleScanConfigType
}

// ScanConfigType gets the scan config type of this base type
func (m *RuntimeScheduleScanConfig) ScanConfigType() RuntimeScheduleScanConfigType {
	return m.scanConfigTypeField
}

// SetScanConfigType sets the scan config type of this base type
func (m *RuntimeScheduleScanConfig) SetScanConfigType(val RuntimeScheduleScanConfigType) {
	m.scanConfigTypeField = val
}

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *RuntimeScheduleScanConfig) UnmarshalJSON(raw []byte) error {
	var data struct {
		CisDockerBenchmarkScanEnabled bool `json:"cisDockerBenchmarkScanEnabled,omitempty"`

		Namespaces []string `json:"namespaces"`

		ScanConfigType json.RawMessage `json:"scanConfigType,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var propScanConfigType RuntimeScheduleScanConfigType
	if string(data.ScanConfigType) != "null" {
		scanConfigType, err := UnmarshalRuntimeScheduleScanConfigType(bytes.NewBuffer(data.ScanConfigType), runtime.JSONConsumer())
		if err != nil && err != io.EOF {
			return err
		}
		propScanConfigType = scanConfigType
	}

	var result RuntimeScheduleScanConfig

	// cisDockerBenchmarkScanEnabled
	result.CisDockerBenchmarkScanEnabled = data.CisDockerBenchmarkScanEnabled

	// namespaces
	result.Namespaces = data.Namespaces

	// scanConfigType
	result.scanConfigTypeField = propScanConfigType

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m RuntimeScheduleScanConfig) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {
		CisDockerBenchmarkScanEnabled bool `json:"cisDockerBenchmarkScanEnabled,omitempty"`

		Namespaces []string `json:"namespaces"`
	}{

		CisDockerBenchmarkScanEnabled: m.CisDockerBenchmarkScanEnabled,

		Namespaces: m.Namespaces,
	})
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		ScanConfigType RuntimeScheduleScanConfigType `json:"scanConfigType,omitempty"`
	}{

		ScanConfigType: m.scanConfigTypeField,
	})
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this runtime schedule scan config
func (m *RuntimeScheduleScanConfig) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateScanConfigType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RuntimeScheduleScanConfig) validateScanConfigType(formats strfmt.Registry) error {
	if swag.IsZero(m.ScanConfigType()) { // not required
		return nil
	}

	if err := m.ScanConfigType().Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("scanConfigType")
		}
		return err
	}

	return nil
}

// ContextValidate validate this runtime schedule scan config based on the context it is used
func (m *RuntimeScheduleScanConfig) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateScanConfigType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RuntimeScheduleScanConfig) contextValidateScanConfigType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.ScanConfigType().ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("scanConfigType")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RuntimeScheduleScanConfig) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RuntimeScheduleScanConfig) UnmarshalBinary(b []byte) error {
	var res RuntimeScheduleScanConfig
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
