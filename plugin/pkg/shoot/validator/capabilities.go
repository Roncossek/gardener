package validator

import (
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener/pkg/apis/core"
)

// CloudProfile Admission: Begin

func ValidateCloudProfileCapabilities(cloudProfileSpec *core.CloudProfileSpec) field.ErrorList {
	var errList field.ErrorList
	// check capabilitiesDefinition
	parsedCapabilitiesDefinition := parseCapabilityValues(cloudProfileSpec.CapabilitiesDefinition)
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
			parsedCapabilitySets, unmarshalErrorList := unmarshalCapabilitySets(machineImageVersion.CapabilitySets, path)
			if unmarshalErrorList != nil {
				errList = append(errList, unmarshalErrorList...)
				continue

			}

			parsedMachineImageCapabilitySets := parseCapabilitySets(parsedCapabilitySets)
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
		parsedMachineTypeCapabilities := parseCapabilityValues(machineType.Capabilities)
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

func (c *validationContext) ValidateCapabilities() field.ErrorList {
	var allErrs field.ErrorList

	if c.cloudProfileSpec.CapabilitiesDefinition == nil {
		// TODO(Roncossek): Remove this check once CapabilitiesDefinition is required in CloudProfile
		return allErrs
	}

	if c.shoot.Spec.Provider.Workers == nil {
		// No workers, no capabilities to validate
		return allErrs
	}

	for i, worker := range c.shoot.Spec.Provider.Workers {
		if worker.Machine.Capabilities == nil {
			// TODO (Roncossek): Load default capabilities from cloudProfile instead of failing
			//     	 	 	 	 OR ensure that architecture is always set?! dunno...
			allErrs = append(allErrs,
				field.Required(field.NewPath("spec", "provider", "workers", string(rune(i)), "machine"),
					"capabilities must be provided"))
			continue
		}

		path := field.NewPath("spec", "provider", "workers").Index(i).Child("machine", "image", "capabilitySets")
		capabilitySets, err := unmarshalCapabilitySets(worker.Machine.Image.CapabilitySets, path)
		if err != nil {
			allErrs = append(allErrs, err...)
			continue
		}

		parsedImageCapabilitySets := parseCapabilitySets(capabilitySets)
		parsedMachineCapabilities := parseCapabilityValues(worker.Machine.Capabilities)
		parsedCapabilitiesDefinition := parseCapabilityValues(core.Capabilities(c.cloudProfileSpec.CapabilitiesDefinition))

		// validate that all capabilities are a subset of the capabilitiesDefinition of the cloudProfile
		// 1. machine type
		allErrs = c.validateWorkerMachineCapabilities(parsedMachineCapabilities, parsedCapabilitiesDefinition, i, allErrs)
		parsedMachineCapabilities = applyDefaultCapabilities(parsedMachineCapabilities, parsedCapabilitiesDefinition)

		// 2. machine image
		allErrs = c.validateWorkerImageVersionCapabilities(parsedImageCapabilitySets, parsedCapabilitiesDefinition, i, allErrs)
		parsedImageCapabilitySets = applyDefaultCapabilitySets(parsedImageCapabilitySets, parsedCapabilitiesDefinition)

		if !areWorkerMachineCapabilitiesFullFilledByImageVersion(parsedMachineCapabilities, parsedImageCapabilitySets) {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "provider", "workers", string(rune(i)), "machine", "capabilities"),
					worker.Machine.Capabilities, "no machineImage fulfills the machine capabilities requirements"))
		}
	}

	return allErrs
}

func applyDefaultCapabilitySets(capabilitySets []ParsedCapabilities, capabilitiesDefinition ParsedCapabilities) []ParsedCapabilities {
	capabilitySetsWithDefaults := make([]ParsedCapabilities, len(capabilitySets))
	for i, capabilitySet := range capabilitySets {
		capabilitySetsWithDefaults[i] = applyDefaultCapabilities(capabilitySet, capabilitiesDefinition)
	}
	return capabilitySetsWithDefaults
}

/**
 * The function applyDefaultCapabilities applies the default capabilities of the definition to the capabilities and returns the resulting capabilities.
 */
func applyDefaultCapabilities(capabilities ParsedCapabilities, capabilitiesDefinition ParsedCapabilities) ParsedCapabilities {
	for capabilityName, capabilityValues := range capabilitiesDefinition {
		if _, exists := capabilities[capabilityName]; !exists {
			// if capability was omitted, the default of the capability definition is used
			capabilities[capabilityName] = CreateCapabilityValueSet(capabilityValues.Values())
		}
	}
	return capabilities
}

func (c *validationContext) validateWorkerImageVersionCapabilities(parsedImageCapabilitySets []ParsedCapabilities, parsedCapabilitiesDefinition ParsedCapabilities, workerIndex int, allErrs field.ErrorList) field.ErrorList {
	path := field.NewPath("spec", "provider", "workers", string(rune(workerIndex)), "machine", "image", "capabilitySets")

	for j, capabilitySet := range parsedImageCapabilitySets {
		for capabilityName, capabilityValues := range capabilitySet {
			if len(capabilityValues) == 0 {
				allErrs = append(allErrs,
					field.Invalid(path.Child("clientID", string(rune(j)), capabilityName),
						c.shoot.Spec.Provider.Workers[workerIndex].Machine.Image.CapabilitySets, "must not contain empty capability values"))
				continue
			}

			if !capabilityValues.IsSubsetOf(parsedCapabilitiesDefinition[capabilityName]) {
				allErrs = append(allErrs,
					field.Invalid(path.Child("clientID", string(rune(j)), capabilityName),
						c.shoot.Spec.Provider.Workers[workerIndex].Machine.Image.CapabilitySets, "must be a subset of the capabilitiesDefinition of the cloudProfile"))
			}
		}

	}
	return allErrs
}

func (c *validationContext) validateWorkerMachineCapabilities(parsedMachineCapabilities ParsedCapabilities, parsedCapabilitiesDefinition ParsedCapabilities, workerIndex int, allErrs field.ErrorList) field.ErrorList {
	path := field.NewPath("spec", "provider", "workers", string(rune(workerIndex)), "machine", "capabilities")

	for capabilityName, capabilityValues := range parsedMachineCapabilities {

		if len(capabilityValues) == 0 {
			allErrs = append(allErrs,
				field.Invalid(path.Child(capabilityName),
					c.shoot.Spec.Provider.Workers[workerIndex].Machine.Capabilities, "must not contain empty capability values"))
			continue
		}

		if !capabilityValues.IsSubsetOf(parsedCapabilitiesDefinition[capabilityName]) {
			allErrs = append(allErrs,
				field.Invalid(path.Child(capabilityName),
					c.shoot.Spec.Provider.Workers[workerIndex].Machine.Capabilities, "must be a subset of the capabilitiesDefinition of the cloudProfile"))
		}
	}
	return allErrs
}

func parseCapabilitySets(capabilitySets []core.Capabilities) []ParsedCapabilities {
	parsedImageCapabilitySets := make([]ParsedCapabilities, len(capabilitySets))
	for j, capabilitySet := range capabilitySets {
		parsedImageCapabilitySets[j] = parseCapabilityValues(capabilitySet)
	}
	return parsedImageCapabilitySets
}

func areWorkerMachineCapabilitiesFullFilledByImageVersion(machineCapabilities ParsedCapabilities, capabilitySets []ParsedCapabilities) bool {
	//check thar at least one capabilities set fulfills the requirements of the worker machine
	oneImageFulfillsCapabilities := false
	for _, capabilitySet := range capabilitySets {
		capabilityIntersection := getCapabilitiesIntersection(machineCapabilities, capabilitySet)
		if !hasEmptyCapabilityValue(capabilityIntersection) {
			oneImageFulfillsCapabilities = true
			break
		}

	}
	return oneImageFulfillsCapabilities
}

// parseCapabilitySets []apiextensionsv1.JSON to []core.Capabilities
func unmarshalCapabilitySets(rawCapabilitySets []apiextensionsv1.JSON, path *field.Path) ([]core.Capabilities, field.ErrorList) {
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

// create intersection of two parsed capabilities
func getCapabilitiesIntersection(capabilities ParsedCapabilities, otherCapabilities ParsedCapabilities) ParsedCapabilities {
	intersection := make(ParsedCapabilities)
	for capabilityName, capabilityValues := range capabilities {
		intersection[capabilityName] = capabilityValues.Intersection(otherCapabilities[capabilityName])
	}
	return intersection
}

func hasEmptyCapabilityValue(capabilities ParsedCapabilities) bool {
	for _, capabilityValues := range capabilities {
		if len(capabilityValues) == 0 {
			return true
		}
	}
	return false
}

func parseCapabilityValues(capabilities core.Capabilities) ParsedCapabilities {
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

// CapabilityValueSet is a set of capability values
type CapabilityValueSet map[string]bool

func CreateCapabilityValueSet(values []string) CapabilityValueSet {
	capabilityValueSet := make(CapabilityValueSet)
	for _, value := range values {
		capabilityValueSet[value] = true
	}
	return capabilityValueSet
}

func (c CapabilityValueSet) Add(value string) {
	c[value] = true
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
