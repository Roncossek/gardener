package validation

import (
	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = FDescribe("CloudProfile Validation Tests ", func() {
	Describe("#ValidateCloudProfile With architecture field", func() {

		var (
			cloudProfile        *core.CloudProfile
			updateStrategyMajor = core.MachineImageUpdateStrategy("major")
			amd64               = "amd64"
		)
		BeforeEach(func() {
			cloudProfile = &core.CloudProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mr-cloud-profile",
				},
				Spec: core.CloudProfileSpec{
					Type: "MrType",
					SeedSelector: &core.SeedSelector{
						LabelSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"Mr": "Label"},
						},
					},
					Kubernetes: core.KubernetesSettings{
						Versions: []core.ExpirableVersion{{
							Version: "0.8.15",
						}},
					},
					CapabilitiesDefinition: map[string]string{
						"architecture":   "amd64,arm64",
						"hypervisorType": "gen1,gen2,gen3",
					},
					MachineImages: []core.MachineImage{{
						Name:           "MrImage",
						UpdateStrategy: &updateStrategyMajor,
						Versions: []core.MachineImageVersion{{
							ExpirableVersion: core.ExpirableVersion{
								Version: "24.12.92",
							},
							CRI:           []core.CRI{{Name: "containerd"}},
							Architectures: []string{"amd64"},
							CapabilitySets: []v1.JSON{
								{Raw: []byte(`{"architecture":"amd64","hypervisorType":"gen2"}`)},
								{Raw: []byte(`{"architecture":"amd64","hypervisorType":"gen2"}`)},
								{Raw: []byte(`{"architecture":"arm64","hypervisorType":"gen1"}`)},
								{Raw: []byte(`{"architecture":"arm64","hypervisorType":"gen2,gen3"}`)},
							},
						}},
					}},
					Regions: []core.Region{{Name: "MrRegion"}},
					MachineTypes: []core.MachineType{{
						Name:         "MrType",
						Architecture: &amd64,
						Capabilities: map[string]string{
							"architecture":   "amd64",
							"hypervisorType": "gen2",
						},
					}},
				},
			}
		})
		It("should accept cloudProfile with dedicated architecture and in capabilitiesDefinition ", func() {
			errorList := ValidateCloudProfile(cloudProfile)
			Expect(errorList).To(BeEmpty())
		})

	})

})
