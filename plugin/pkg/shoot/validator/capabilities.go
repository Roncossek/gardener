package validator

import (
	coreValidation "github.com/gardener/gardener/pkg/apis/core/validation"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener/pkg/apis/core"
)

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
		capabilitySets, err := coreValidation.UnmarshalCapabilitySets(worker.Machine.Image.CapabilitySets, path)
		if err != nil {
			allErrs = append(allErrs, err...)
			continue
		}

		parsedImageCapabilitySets := coreValidation.ParseCapabilitySets(capabilitySets)
		parsedMachineCapabilities := coreValidation.ParseCapabilityValues(worker.Machine.Capabilities)
		parsedCapabilitiesDefinition := coreValidation.ParseCapabilityValues(core.Capabilities(c.cloudProfileSpec.CapabilitiesDefinition))

		// validate that all capabilities are a subset of the capabilitiesDefinition of the cloudProfile
		// 1. machine type
		allErrs = c.validateWorkerMachineCapabilities(parsedMachineCapabilities, parsedCapabilitiesDefinition, i, allErrs)
		parsedMachineCapabilities = coreValidation.ApplyDefaultCapabilities(parsedMachineCapabilities, parsedCapabilitiesDefinition)

		// 2. machine image
		allErrs = c.validateWorkerImageVersionCapabilities(parsedImageCapabilitySets, parsedCapabilitiesDefinition, i, allErrs)
		parsedImageCapabilitySets = coreValidation.ApplyDefaultCapabilitySets(parsedImageCapabilitySets, parsedCapabilitiesDefinition)

		if !coreValidation.AreWorkerMachineCapabilitiesFullFilledByImageVersion(parsedMachineCapabilities, parsedImageCapabilitySets) {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "provider", "workers", string(rune(i)), "machine", "capabilities"),
					worker.Machine.Capabilities, "no machineImage fulfills the machine capabilities requirements"))
		}
	}

	return allErrs
}

func (c *validationContext) validateWorkerImageVersionCapabilities(
	parsedImageCapabilitySets []coreValidation.ParsedCapabilities,
	parsedCapabilitiesDefinition coreValidation.ParsedCapabilities,
	workerIndex int, allErrs field.ErrorList,
) field.ErrorList {
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

func (c *validationContext) validateWorkerMachineCapabilities(
	parsedMachineCapabilities coreValidation.ParsedCapabilities,
	parsedCapabilitiesDefinition coreValidation.ParsedCapabilities,
	workerIndex int, allErrs field.ErrorList) field.ErrorList {
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
