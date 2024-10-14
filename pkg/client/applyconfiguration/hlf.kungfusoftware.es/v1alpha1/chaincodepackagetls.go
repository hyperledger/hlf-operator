/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// ChaincodePackageTLSApplyConfiguration represents a declarative configuration of the ChaincodePackageTLS type for use
// with apply.
type ChaincodePackageTLSApplyConfiguration struct {
	Required *bool `json:"required,omitempty"`
}

// ChaincodePackageTLSApplyConfiguration constructs a declarative configuration of the ChaincodePackageTLS type for use with
// apply.
func ChaincodePackageTLS() *ChaincodePackageTLSApplyConfiguration {
	return &ChaincodePackageTLSApplyConfiguration{}
}

// WithRequired sets the Required field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Required field is set to the value of the last call.
func (b *ChaincodePackageTLSApplyConfiguration) WithRequired(value bool) *ChaincodePackageTLSApplyConfiguration {
	b.Required = &value
	return b
}
