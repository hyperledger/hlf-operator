/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricNetworkConfigSpecApplyConfiguration represents a declarative configuration of the FabricNetworkConfigSpec type for use
// with apply.
type FabricNetworkConfigSpecApplyConfiguration struct {
	Organization           *string                                                      `json:"organization,omitempty"`
	Internal               *bool                                                        `json:"internal,omitempty"`
	Organizations          []string                                                     `json:"organizations,omitempty"`
	OrganizationConfig     map[string]FabricNetworkConfigOrganizationApplyConfiguration `json:"organizationConfig,omitempty"`
	Namespaces             []string                                                     `json:"namespaces,omitempty"`
	CertificateAuthorities []FabricNetworkConfigCAApplyConfiguration                    `json:"certificateAuthorities,omitempty"`
	Channels               []string                                                     `json:"channels,omitempty"`
	Identities             []FabricNetworkConfigIdentityApplyConfiguration              `json:"identities,omitempty"`
	ExternalOrderers       []FabricNetworkConfigExternalOrdererApplyConfiguration       `json:"externalOrderers,omitempty"`
	ExternalPeers          []FabricNetworkConfigExternalPeerApplyConfiguration          `json:"externalPeers,omitempty"`
	SecretName             *string                                                      `json:"secretName,omitempty"`
}

// FabricNetworkConfigSpecApplyConfiguration constructs a declarative configuration of the FabricNetworkConfigSpec type for use with
// apply.
func FabricNetworkConfigSpec() *FabricNetworkConfigSpecApplyConfiguration {
	return &FabricNetworkConfigSpecApplyConfiguration{}
}

// WithOrganization sets the Organization field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Organization field is set to the value of the last call.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithOrganization(value string) *FabricNetworkConfigSpecApplyConfiguration {
	b.Organization = &value
	return b
}

// WithInternal sets the Internal field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Internal field is set to the value of the last call.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithInternal(value bool) *FabricNetworkConfigSpecApplyConfiguration {
	b.Internal = &value
	return b
}

// WithOrganizations adds the given value to the Organizations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Organizations field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithOrganizations(values ...string) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		b.Organizations = append(b.Organizations, values[i])
	}
	return b
}

// WithOrganizationConfig puts the entries into the OrganizationConfig field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the OrganizationConfig field,
// overwriting an existing map entries in OrganizationConfig field with the same key.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithOrganizationConfig(entries map[string]FabricNetworkConfigOrganizationApplyConfiguration) *FabricNetworkConfigSpecApplyConfiguration {
	if b.OrganizationConfig == nil && len(entries) > 0 {
		b.OrganizationConfig = make(map[string]FabricNetworkConfigOrganizationApplyConfiguration, len(entries))
	}
	for k, v := range entries {
		b.OrganizationConfig[k] = v
	}
	return b
}

// WithNamespaces adds the given value to the Namespaces field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Namespaces field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithNamespaces(values ...string) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		b.Namespaces = append(b.Namespaces, values[i])
	}
	return b
}

// WithCertificateAuthorities adds the given value to the CertificateAuthorities field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the CertificateAuthorities field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithCertificateAuthorities(values ...*FabricNetworkConfigCAApplyConfiguration) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithCertificateAuthorities")
		}
		b.CertificateAuthorities = append(b.CertificateAuthorities, *values[i])
	}
	return b
}

// WithChannels adds the given value to the Channels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Channels field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithChannels(values ...string) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		b.Channels = append(b.Channels, values[i])
	}
	return b
}

// WithIdentities adds the given value to the Identities field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Identities field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithIdentities(values ...*FabricNetworkConfigIdentityApplyConfiguration) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithIdentities")
		}
		b.Identities = append(b.Identities, *values[i])
	}
	return b
}

// WithExternalOrderers adds the given value to the ExternalOrderers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ExternalOrderers field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithExternalOrderers(values ...*FabricNetworkConfigExternalOrdererApplyConfiguration) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithExternalOrderers")
		}
		b.ExternalOrderers = append(b.ExternalOrderers, *values[i])
	}
	return b
}

// WithExternalPeers adds the given value to the ExternalPeers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ExternalPeers field.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithExternalPeers(values ...*FabricNetworkConfigExternalPeerApplyConfiguration) *FabricNetworkConfigSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithExternalPeers")
		}
		b.ExternalPeers = append(b.ExternalPeers, *values[i])
	}
	return b
}

// WithSecretName sets the SecretName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecretName field is set to the value of the last call.
func (b *FabricNetworkConfigSpecApplyConfiguration) WithSecretName(value string) *FabricNetworkConfigSpecApplyConfiguration {
	b.SecretName = &value
	return b
}
