package validation

import (
	"github.com/gardener/gardener/pkg/apis/core"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"strings"

	"k8s.io/apimachinery/pkg/util/json"
)

// CloudProfile Defaulter: Begin
// THis defaulting is designed to assist during the transition to capabilities and to remove the dedicated architecture field
// once the dedicated architecture field is removed, the defaulting should be removed as well

// this default is to be removed once the capabilitiesDefinition is required in CloudProfile
const DefaultedArchitecture = "amd64"

// defaultCloudProfileCapabilities sets the default values for the capabilities of a CloudProfile
// this function is designed to be removed once the capabilitiesDefinition is required in CloudProfile
func defaultCloudProfileCapabilities(cloudProfileSpec *core.CloudProfileSpec) {
	if cloudProfileSpec.CapabilitiesDefinition == nil {
		cloudProfileSpec.CapabilitiesDefinition = map[string]string{"architecture": DefaultedArchitecture}
	}
}

// defaultMachineTypeArchitecture sets the default values for the capabilities of a MachineType
func defaultMachineTypeArchitecture(machineType core.MachineType, capabilitiesDefinition core.Capabilities, path field.Path) core.MachineType {
	usedArchitecture := capabilitiesDefinition["architecture"]
	if machineType.Capabilities == nil {
		machineType.Capabilities = make(core.Capabilities)
	}

	// Cases:
	// 1. machineType.Capabilities.Architecture is set && machineType.Architecture is set 		=> machineType.Capabilities.Architecture
	// 2. machineType.Capabilities.Architecture is set && machineType.Architecture is nil 		=> machineType.Capabilities.Architecture

	// 3. machineType.Capabilities.Architecture is nil && machineType.Architecture is set 		=> machineType.Architecture

	// 4. machineType.Capabilities.Architecture is nil && machineType.Architecture is nil 		=> use default architecture from capabilitiesDefinition

	if len(machineType.Capabilities["architecture"]) != 0 {
		usedArchitecture = machineType.Capabilities["architecture"]
	} else if machineType.Architecture != nil {
		usedArchitecture = *machineType.Architecture
	}

	machineType.Capabilities["architecture"] = usedArchitecture
	machineType.Architecture = &usedArchitecture

	return machineType
}

// defaultMachineImageArchitecture sets the default values for the capabilitiesSets of a MachineImageVersion
func defaultMachineImageArchitecture(machineImageVersion core.MachineImageVersion, capabilitiesDefinition core.Capabilities, path field.Path) (core.MachineImageVersion, field.ErrorList) {
	var errList field.ErrorList
	parsedCapabilitiesDefinition := ParseCapabilityValues(capabilitiesDefinition)
	usedArchitectures := parsedCapabilitiesDefinition["architecture"].Values()

	if machineImageVersion.CapabilitySets == nil {
		machineImageVersion.CapabilitySets = []apiextensionsv1.JSON{}
	}

	// if the architecture is set in the capabilitySets, it is used no need to check rest
	architectureSet := CapabilityValueSet{}
	if len(machineImageVersion.CapabilitySets) != 0 {
		for i, capabilitySet := range machineImageVersion.CapabilitySets {
			parsedCapabilitySet, err := UnmarshalCapabilitySets([]apiextensionsv1.JSON{capabilitySet}, path.Index(i))
			if err != nil {
				errList = append(errList, err...)
			}
			parsedCapabilitySets := ParseCapabilitySets(parsedCapabilitySet)
			for _, parsedCapabilitySet := range parsedCapabilitySets {
				if len(parsedCapabilitySet["architecture"]) != 0 {
					architectureSet.Add(parsedCapabilitySet["architecture"].Values()...)
				}

			}
		}

	}

	if len(architectureSet) != 0 {
		usedArchitectures = architectureSet.Values()
	} else if machineImageVersion.Architectures != nil && len(machineImageVersion.Architectures) != 0 {
		usedArchitectures = machineImageVersion.Architectures
	}

	machineImageVersion.Architectures = usedArchitectures

	var capabilitiesSet []core.Capabilities
	if len(machineImageVersion.CapabilitySets) == 0 {
		for _, architecture := range usedArchitectures {
			capabilitiesSet = append(capabilitiesSet, core.Capabilities{"architecture": architecture})
		}
	} else {
		for i, capabilitySet := range machineImageVersion.CapabilitySets {
			capabilitiesSet, err := UnmarshalCapabilitySets([]apiextensionsv1.JSON{capabilitySet}, path.Index(i))
			if err != nil {
				errList = append(errList, err...)
			}

			// WTF is this? Get this *** together
			parsedCapabilitySets := ParseCapabilitySets(capabilitiesSet)
			var finalCapabilitySets []core.Capabilities
			for _, parsedCapabilitySet := range parsedCapabilitySets {
				if len(parsedCapabilitySet["architecture"]) == 0 {
					// add capabilities per architecture that was selected for this version
					// account for the case that capabilities are already present.... Maybe we should just reject this case?! ... yeah sounds reasonable actually for the cloudprofile at least.
					// then allways check the cloudprofile for the capabilities in case of existing shoots, then single source of truth is the cloudprofile
					for j, architecture := range usedArchitectures {
						if j == 0 {
							parsedCapabilitySet["architecture"] = CreateCapabilityValueSet([]string{architecture})

						} else {
							parsedCapabilitySet = parsedCapabilitySet.Copy()
							parsedCapabilitySet["architecture"] = CreateCapabilityValueSet([]string{architecture})
						}
						finalCapabilitySets = append(finalCapabilitySets, parsedCapabilitySet.toCapabilityMap())
					}
					parsedCapabilitySet["architecture"] = CreateCapabilityValueSet(usedArchitectures)
				}
				finalCapabilitySets = append(finalCapabilitySets, parsedCapabilitySet.toCapabilityMap())
			}
			machineImageVersion.CapabilitySets, err = MarshalCapabilitiesSets(finalCapabilitySets, path.Index(i))
			if err != nil {
				errList = append(errList, err...)
			}
		}

	}

	return machineImageVersion, errList
}

// CloudProfile Defaulter: End

// CloudProfile Admission: Begin

func ValidateCloudProfileCapabilities(cloudProfileSpec *core.CloudProfileSpec) field.ErrorList {
	var errList field.ErrorList
	// check capabilitiesDefinition
	parsedCapabilitiesDefinition := ParseCapabilityValues(cloudProfileSpec.CapabilitiesDefinition)
	errList = validateCapabilitiesDefinition(parsedCapabilitiesDefinition)

	// check if machines are using valid capabilities
	errList = append(errList, validateMachineTypesCapabilities(cloudProfileSpec, parsedCapabilitiesDefinition)...)

	// check if machine images are using valid capabilitiesSets
	errList = append(errList, validateMachineImagesCapabilities(cloudProfileSpec, parsedCapabilitiesDefinition)...)

	// TODO (Roncossek): Add validation for providerConfigurations

	return errList
}

func validateMachineImagesCapabilities(cloudProfileSpec *core.CloudProfileSpec, capabilitiesDefinition ParsedCapabilities) field.ErrorList {
	var errList field.ErrorList
	osDistributions := cloudProfileSpec.MachineImages
	for i, osDistribution := range osDistributions {
		machineImageVersions := osDistribution.Versions

		for j, machineImageVersion := range machineImageVersions {

			path := field.NewPath("spec", "machineImages", string(rune(i)), "versions", string(rune(j)), "capabilitySets")
			parsedCapabilitySets, unmarshalErrorList := UnmarshalCapabilitySets(machineImageVersion.CapabilitySets, path)
			if unmarshalErrorList != nil {
				errList = append(errList, unmarshalErrorList...)
				continue

			}

			parsedMachineImageCapabilitySets := ParseCapabilitySets(parsedCapabilitySets)
			for _, parsedMachineImageCapabilitySet := range parsedMachineImageCapabilitySets {
				errList = append(errList, validateCapabilitiesAgainstDefinition(parsedMachineImageCapabilitySet, capabilitiesDefinition, path)...)
			}
		}
	}

	return errList

}

func validateMachineTypesCapabilities(cloudProfileSpec *core.CloudProfileSpec, capabilitiesDefinition ParsedCapabilities) field.ErrorList {
	var errList field.ErrorList
	machineTypes := cloudProfileSpec.MachineTypes
	for i, machineType := range machineTypes {
		parsedMachineTypeCapabilities := ParseCapabilityValues(machineType.Capabilities)
		path := field.NewPath("spec", "machineTypes", string(rune(i)), "capabilities")
		errList = append(errList, validateCapabilitiesAgainstDefinition(parsedMachineTypeCapabilities, capabilitiesDefinition, path)...)
	}

	return errList
}

func validateCapabilitiesAgainstDefinition(capabilities ParsedCapabilities, capabilitiesDefinition ParsedCapabilities, path *field.Path) field.ErrorList {
	var errList field.ErrorList

	for capabilityName, capabilityValues := range capabilities {
		if len(capabilityValues) == 0 {
			errList = append(errList, field.Invalid(path.Child(capabilityName), capabilityValues, "must not be empty"))
			continue
		}
		if !capabilityValues.IsSubsetOf(capabilitiesDefinition[capabilityName]) {
			errList = append(errList, field.Invalid(path.Child(capabilityName), capabilityValues, "must be a subset of spec.capabilitiesDefinition of the providers cloudProfile"))
		}
	}

	return errList
}

func validateCapabilitiesDefinition(definition ParsedCapabilities) field.ErrorList {
	var errList field.ErrorList

	// No empty capabilities allowed
	for capabilityName, capabilityValues := range definition {
		if len(capabilityValues) == 0 {
			errList = append(errList, field.Invalid(field.NewPath("capabilitiesDefinition", capabilityName), capabilityValues, "must not be empty"))
		}
	}
	return errList
}

// CloudProfile Admission: End

// Shoot Admission: Begin

func ApplyDefaultCapabilitySets(capabilitySets []ParsedCapabilities, capabilitiesDefinition ParsedCapabilities) []ParsedCapabilities {
	capabilitySetsWithDefaults := make([]ParsedCapabilities, len(capabilitySets))
	for i, capabilitySet := range capabilitySets {
		capabilitySetsWithDefaults[i] = ApplyDefaultCapabilities(capabilitySet, capabilitiesDefinition)
	}
	return capabilitySetsWithDefaults
}

/**
 * The function ApplyDefaultCapabilities applies the default capabilities of the definition to the capabilities and returns the resulting capabilities.
 */
func ApplyDefaultCapabilities(capabilities ParsedCapabilities, capabilitiesDefinition ParsedCapabilities) ParsedCapabilities {
	for capabilityName, capabilityValues := range capabilitiesDefinition {
		if _, exists := capabilities[capabilityName]; !exists {
			// if capability was omitted, the default of the capability definition is used
			capabilities[capabilityName] = CreateCapabilityValueSet(capabilityValues.Values())
		}
	}
	return capabilities
}

func AreWorkerMachineCapabilitiesFullFilledByImageVersion(machineCapabilities ParsedCapabilities, capabilitySets []ParsedCapabilities) bool {
	//check thar at least one capabilities set fulfills the requirements of the worker machine
	oneImageFulfillsCapabilities := false
	for _, capabilitySet := range capabilitySets {
		capabilityIntersection := GetCapabilitiesIntersection(machineCapabilities, capabilitySet)
		if !HasEmptyCapabilityValue(capabilityIntersection) {
			oneImageFulfillsCapabilities = true
			break
		}

	}
	return oneImageFulfillsCapabilities
}

// Shoot Admission: End

// Generic Functions: Begin

func ParseCapabilitySets(capabilitySets []core.Capabilities) []ParsedCapabilities {
	parsedImageCapabilitySets := make([]ParsedCapabilities, len(capabilitySets))
	for j, capabilitySet := range capabilitySets {
		parsedImageCapabilitySets[j] = ParseCapabilityValues(capabilitySet)
	}
	return parsedImageCapabilitySets
}

// ParseCapabilitySets []apiextensionsv1.JSON to []core.Capabilities
func UnmarshalCapabilitySets(rawCapabilitySets []apiextensionsv1.JSON, path *field.Path) ([]core.Capabilities, field.ErrorList) {
	var allErrs field.ErrorList
	capabilitySets := make([]core.Capabilities, len(rawCapabilitySets))
	for i, rawCapabilitySet := range rawCapabilitySets {
		capabilities := core.Capabilities{}
		err := json.Unmarshal(rawCapabilitySet.Raw, &capabilities)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(path.Child(string(rune(i))), rawCapabilitySet, "must be a valid capabilities definition: "+err.Error()))
		}
		capabilitySets[i] = capabilities
	}

	// TODO (Roncossek): Validate that the capabilities are not empty and correctly unmarshalled
	return capabilitySets, allErrs
}

func MarshalCapabilitiesSets(capabilitiesSets []core.Capabilities, path *field.Path) ([]apiextensionsv1.JSON, field.ErrorList) {
	var allErrs field.ErrorList
	returnJSONs := make([]apiextensionsv1.JSON, len(capabilitiesSets))

	for _, capabilities := range capabilitiesSets {
		rawJSON, err := json.Marshal(capabilities)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(path, capabilities, "must be a valid capabilities definition: "+err.Error()))
		}
		returnJSONs = append(returnJSONs, apiextensionsv1.JSON{Raw: rawJSON})
	}
	return returnJSONs, allErrs
}

// create intersection of two parsed capabilities
func GetCapabilitiesIntersection(capabilities ParsedCapabilities, otherCapabilities ParsedCapabilities) ParsedCapabilities {
	intersection := make(ParsedCapabilities)
	for capabilityName, capabilityValues := range capabilities {
		intersection[capabilityName] = capabilityValues.Intersection(otherCapabilities[capabilityName])
	}
	return intersection
}

func HasEmptyCapabilityValue(capabilities ParsedCapabilities) bool {
	for _, capabilityValues := range capabilities {
		if len(capabilityValues) == 0 {
			return true
		}
	}
	return false
}

func ParseCapabilityValues(capabilities core.Capabilities) ParsedCapabilities {
	parsedCapabilities := make(ParsedCapabilities)
	for capabilityName, capabilityValuesString := range capabilities {
		capabilityValues := splitAndSanitize(capabilityValuesString)
		parsedCapabilities[capabilityName] = CreateCapabilityValueSet(capabilityValues)

	}
	return parsedCapabilities
}

// function to return sanitized values of a comma separated string
// e.g. ",a ,'b', c" -> ["a", "b", "c"]
func splitAndSanitize(valueString string) []string {
	values := strings.Split(valueString, ",")
	for i := 0; i < len(values); i++ {

		// strip leading and trailing whitespaces
		values[i] = strings.TrimSpace(values[i])
		// strip leading and trailing single quotes
		values[i] = strings.Trim(values[i], "'")
		// strip leading and trailing double quotes
		values[i] = strings.Trim(values[i], "\"")

		if len(strings.TrimSpace(values[i])) == 0 {
			values = append(values[:i], values[i+1:]...)
			i--
		}
	}
	return values
}

// ParsedCapabilities is the internal runtime representation of Capabilities
type ParsedCapabilities map[string]CapabilityValueSet

func (c ParsedCapabilities) Copy() ParsedCapabilities {
	capabilities := make(ParsedCapabilities)
	for capabilityName, capabilityValueSet := range c {
		capabilities[capabilityName] = CreateCapabilityValueSet(capabilityValueSet.Values())
	}
	return capabilities
}

func (c ParsedCapabilities) toCapabilityMap() core.Capabilities {
	var capabilities core.Capabilities
	for capabilityName, capabilityValueSet := range c {
		capabilities[capabilityName] = strings.Join(capabilityValueSet.Values(), ",")
	}
	return capabilities
}

// CapabilityValueSet is a set of capability values
type CapabilityValueSet map[string]bool

func CreateCapabilityValueSet(values []string) CapabilityValueSet {
	capabilityValueSet := make(CapabilityValueSet)
	for _, value := range values {
		capabilityValueSet[value] = true
	}
	return capabilityValueSet
}

func (c CapabilityValueSet) Add(values ...string) {
	for _, value := range values {
		c[value] = true
	}
}

func (c CapabilityValueSet) Contains(value string) bool {
	_, ok := c[value]
	return ok
}

func (c CapabilityValueSet) Remove(value string) {
	delete(c, value)
}

func (c CapabilityValueSet) Values() []string {
	values := make([]string, 0, len(c))
	for value := range c {
		values = append(values, value)
	}
	return values
}
func (c CapabilityValueSet) Intersection(other CapabilityValueSet) CapabilityValueSet {
	intersection := make(CapabilityValueSet)
	for value := range c {
		if other.Contains(value) {
			intersection.Add(value)
		}
	}
	return intersection
}

func (c CapabilityValueSet) IsSubsetOf(other CapabilityValueSet) bool {
	for value := range c {
		if !other.Contains(value) {
			return false
		}
	}
	return true
}

// Generic Functions: End
