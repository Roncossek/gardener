package validator

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencoreinformers "github.com/gardener/gardener/pkg/client/core/informers/externalversions"
	securityinformers "github.com/gardener/gardener/pkg/client/security/informers/externalversions"
	"github.com/gardener/gardener/third_party/mock/apiserver/authorization/authorizer"
)

var _ = Describe("Capabilities", func() {

	var (
		ctx      context.Context
		userInfo = &user.DefaultInfo{Name: "foo"}

		cloudProfile   gardencorev1beta1.CloudProfile
		versionedShoot gardencorev1beta1.Shoot
		shoot          core.Shoot

		validMachineImageVersions = []gardencorev1beta1.MachineImageVersion{
			{
				ExpirableVersion: gardencorev1beta1.ExpirableVersion{
					Version: "0.0.1",
				},
				CRI: []gardencorev1beta1.CRI{
					{
						Name: gardencorev1beta1.CRINameContainerD,
						ContainerRuntimes: []gardencorev1beta1.ContainerRuntime{
							{
								Type: "test-cr",
							},
						},
					},
				},
				Architectures:  []string{"amd64", "arm64"},
				CapabilitySets: make([]apiextensionsv1.JSON, 0),
			},
		}
	)
	BeforeEach(func() {
		validMachineImageName := "my-machine-image"
		volumeType := "volume-type-1"

		capabilities := make(gardencorev1beta1.Capabilities)
		capabilities["architecture"] = "amd64"
		capabilities["hypervisorType"] = "gen1,gen2"
		rawCapabilities, _ := json.Marshal(capabilities)

		validMachineImageVersions[0].CapabilitySets = append(validMachineImageVersions[0].CapabilitySets, apiextensionsv1.JSON{Raw: rawCapabilities})
		validMachineImageVersions[0].CapabilitySets = append(validMachineImageVersions[0].CapabilitySets, apiextensionsv1.JSON{Raw: rawCapabilities})

		capabilitiesDefinitions := make(gardencorev1beta1.Capabilities)
		capabilitiesDefinitions["architecture"] = "arm64,amd64"
		capabilitiesDefinitions["hypervisorType"] = "gen1,gen2,gen3"
		cloudProfile = gardencorev1beta1.CloudProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: "profile",
			},
			Spec: gardencorev1beta1.CloudProfileSpec{
				Type:                   "unknown",
				CapabilitiesDefinition: capabilitiesDefinitions,
				Kubernetes: gardencorev1beta1.KubernetesSettings{
					Versions: []gardencorev1beta1.ExpirableVersion{{Version: "1.6.4"}},
				},
				MachineImages: []gardencorev1beta1.MachineImage{
					{
						Name:     validMachineImageName,
						Versions: validMachineImageVersions,
					},
				},
				MachineTypes: []gardencorev1beta1.MachineType{
					{
						Name:         "machine-type-old",
						CPU:          resource.MustParse("2"),
						GPU:          resource.MustParse("0"),
						Memory:       resource.MustParse("100Gi"),
						Usable:       ptr.To(false),
						Architecture: ptr.To("amd64"),
					},
					{
						Name:         "machine-type-1",
						CPU:          resource.MustParse("2"),
						GPU:          resource.MustParse("0"),
						Memory:       resource.MustParse("100Gi"),
						Architecture: ptr.To("arm64"),
						Usable:       ptr.To(true),
						Capabilities: capabilities,
					},
				},
				VolumeTypes: []gardencorev1beta1.VolumeType{
					{
						Name:   volumeType,
						Class:  "super-premium",
						Usable: ptr.To(true),
					},
				},
				Regions: []gardencorev1beta1.Region{
					{
						Name:  "europe",
						Zones: []gardencorev1beta1.AvailabilityZone{{Name: "europe-a"}},
					},
					{
						Name:  "asia",
						Zones: []gardencorev1beta1.AvailabilityZone{{Name: "asia-a"}},
					},
				},
			},
		}
		shoot = core.Shoot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shoot",
				Namespace: "my-namespace",
			},
			Spec: core.ShootSpec{
				CloudProfileName: ptr.To("profile"),
				Region:           "europe",
				Kubernetes: core.Kubernetes{
					Version:                     "1.6.4",
					EnableStaticTokenKubeconfig: ptr.To(true),
					KubeControllerManager: &core.KubeControllerManagerConfig{
						NodeMonitorGracePeriod: &metav1.Duration{Duration: 40 * time.Second},
					},
				},
				Networking: &core.Networking{
					IPFamilies: []core.IPFamily{
						core.IPFamilyIPv4,
					},
				},
				Provider: core.Provider{
					Type: "unknown",
					Workers: []core.Worker{
						{
							Name: "worker-name",
							Machine: core.Machine{
								Type: "machine-type-1",
								Image: &core.ShootMachineImage{
									Name: validMachineImageName,
								},
								Architecture: ptr.To("arm64"),
								Capabilities: core.Capabilities(capabilities),
							},
							Minimum: 1,
							Maximum: 1,
							Volume: &core.Volume{
								VolumeSize: "40Gi",
								Type:       &volumeType,
							},
							Zones: []string{"europe-a"},
						},
					},
					WorkersSettings: &core.WorkersSettings{
						SSHAccess: &core.SSHAccess{
							Enabled: true,
						},
					},
					InfrastructureConfig: &runtime.RawExtension{Raw: []byte(`{
"kind": "InfrastructureConfig",
"apiVersion": "some.random.config/v1beta1"}`)},
				},
			},
		}
		err := gardencorev1beta1.Convert_core_Shoot_To_v1beta1_Shoot(&shoot, &versionedShoot, nil)
		Expect(err).ToNot(HaveOccurred())

		fmt.Printf("%v,%v,%v", cloudProfile, versionedShoot, validMachineImageVersions)
		ctx = context.Background()

	})

	Context("CloudProfile capabilities checks", func() {
		It("should accept shoots with valid machine types and image version combination", func() {
			// create instance of the admission validator and set relevant properties
			var admissionHandler, _ = New()

			var auth *authorizer.MockAuthorizer = nil
			admissionHandler.SetAuthorizer(auth)
			admissionHandler.AssignReadyFunc(func() bool { return true })
			var kubeInformerFactory = kubeinformers.NewSharedInformerFactory(nil, 0)
			admissionHandler.SetKubeInformerFactory(kubeInformerFactory)
			var coreInformerFactory = gardencoreinformers.NewSharedInformerFactory(nil, 0)
			admissionHandler.SetCoreInformerFactory(coreInformerFactory)
			var securityInformerFactory = securityinformers.NewSharedInformerFactory(nil, 0)
			admissionHandler.SetSecurityInformerFactory(securityInformerFactory)

			// prepare data/objects used in the test
			projectName := "my-project"
			namespaceName := "my-namespace"
			var project = gardencorev1beta1.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name: projectName,
				},
				Spec: gardencorev1beta1.ProjectSpec{
					Namespace: &namespaceName,
				},
			}

			// add test resources to datastore
			Expect(coreInformerFactory.Core().V1beta1().Projects().Informer().GetStore().Add(&project)).To(Succeed())
			Expect(coreInformerFactory.Core().V1beta1().CloudProfiles().Informer().GetStore().Add(&cloudProfile)).To(Succeed())

			// test the admission handler
			attrs := admission.NewAttributesRecord(&shoot, nil, core.Kind("Shoot").WithVersion("version"), shoot.Namespace, shoot.Name, core.Resource("shoots").WithVersion("version"), "", admission.Create, &metav1.CreateOptions{}, false, userInfo)
			err := admissionHandler.Admit(ctx, attrs, nil)

			Expect(err).NotTo(HaveOccurred())

		})
	})
})
