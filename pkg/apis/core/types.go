// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// GardenerSeedLeaseNamespace is the namespace in which Gardenlet will report Seeds'
	// status using Lease resources for each Seed
	GardenerSeedLeaseNamespace = "gardener-system-seed-lease"
	// GardenerShootIssuerNamespace is the namespace in which Gardenlet
	// will sync service account issuer discovery documents
	// of Shoot clusters which require managed issuer
	GardenerShootIssuerNamespace = "gardener-system-shoot-issuer"
	// GardenerSystemPublicNamespace is the namespace which will contain a resources
	// describing gardener installation itself. The resources in this namespace
	// may be visible to all authenticated users.
	GardenerSystemPublicNamespace = "gardener-system-public"
)

// Object is a core object resource.
type Object interface {
	metav1.Object
}

// IPFamily is a type for specifying an IP protocol version to use in Gardener clusters.
type IPFamily string

const (
	// IPFamilyIPv4 is the IPv4 IP family.
	IPFamilyIPv4 IPFamily = "IPv4"
	// IPFamilyIPv6 is the IPv6 IP family.
	IPFamilyIPv6 IPFamily = "IPv6"
)

// IsIPv4SingleStack determines whether the given list of IP families specifies IPv4 single-stack networking.
func IsIPv4SingleStack(ipFamilies []IPFamily) bool {
	return len(ipFamilies) == 0 || (len(ipFamilies) == 1 && ipFamilies[0] == IPFamilyIPv4)
}

// IsIPv6SingleStack determines whether the given list of IP families specifies IPv6 single-stack networking.
func IsIPv6SingleStack(ipFamilies []IPFamily) bool {
	return len(ipFamilies) == 1 && ipFamilies[0] == IPFamilyIPv6
}

// AccessRestriction describes an access restriction for a Kubernetes cluster (e.g., EU access-only).
type AccessRestriction struct {
	// Name is the name of the restriction.
	Name string
}

// AccessRestrictionWithOptions describes an access restriction for a Kubernetes cluster (e.g., EU access-only) and
// allows to specify additional options.
type AccessRestrictionWithOptions struct {
	AccessRestriction
	// Options is a map of additional options for the access restriction.
	// +optional
	Options map[string]string
}

// CapabilityValues is a list of values for a capability.
// The type is wrapped to represent the values as a comma-separated string in JSON.
type CapabilityValues struct {
	Values []string
}

// Capabilities of a machine type or machine image.
type Capabilities map[string]CapabilityValues

// CapabilitiesSetCapabilities is a wrapper for Capabilities
// this is a workaround as we cannot define a slice of maps in protobuf
// we define custom marshal/unmarshal functions to get around this l
// If there is a way to avoid this, we should do it.
type CapabilitiesSetCapabilities struct {
	Capabilities Capabilities `json:"-"`
}

// Contains checks if the CapabilityValues contains all values
func (c *CapabilityValues) Contains(values ...string) bool {
	for _, value := range values {
		if !contains(c.Values, value) {
			return false
		}
	}
	return true
}

// contains checks if an array contains a specific element
func contains(arr []string, target string) bool {
	for _, element := range arr {
		if element == target {
			return true
		}
	}
	return false
}

// IsSubsetOf checks if the CapabilityValues is a subset of another CapabilityValues
func (c *CapabilityValues) IsSubsetOf(other CapabilityValues) bool {
	for _, value := range c.Values {
		if !other.Contains(value) {
			return false
		}
	}
	return true
}

// HasEntries checks if a Capability is defined.
func (capabilities Capabilities) HasEntries() bool {
	return len(capabilities) != 0
}
