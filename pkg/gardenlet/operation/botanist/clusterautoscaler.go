// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package botanist

import (
	"context"
	"fmt"
	"math"
	"math/big"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener/imagevector"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/component/autoscaling/clusterautoscaler"
	"github.com/gardener/gardener/pkg/utils"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
)

// DefaultClusterAutoscaler returns a deployer for the cluster-autoscaler.
func (b *Botanist) DefaultClusterAutoscaler() (clusterautoscaler.Interface, error) {
	image, err := imagevector.Containers().FindImage(imagevector.ContainerImageNameClusterAutoscaler, imagevectorutils.RuntimeVersion(b.SeedVersion()), imagevectorutils.TargetVersion(b.ShootVersion()))
	if err != nil {
		return nil, err
	}

	return clusterautoscaler.New(
		b.SeedClientSet.Client(),
		b.Shoot.ControlPlaneNamespace,
		b.SecretsManager,
		image.String(),
		b.Shoot.GetReplicas(1),
		b.Shoot.GetInfo().Spec.Kubernetes.ClusterAutoscaler,
		b.Shoot.GetInfo().Spec.Provider.Workers,
		b.Seed.KubernetesVersion,
	), nil
}

// DeployClusterAutoscaler deploys the Kubernetes cluster-autoscaler.
func (b *Botanist) DeployClusterAutoscaler(ctx context.Context) error {
	if b.Shoot.WantsClusterAutoscaler {
		replicas, err := b.determineControllerReplicas(ctx, v1beta1constants.DeploymentNameClusterAutoscaler, 1)
		if err != nil {
			return err
		}
		b.Shoot.Components.ControlPlane.ClusterAutoscaler.SetReplicas(replicas)
		b.Shoot.Components.ControlPlane.ClusterAutoscaler.SetNamespaceUID(b.SeedNamespaceObject.UID)
		b.Shoot.Components.ControlPlane.ClusterAutoscaler.SetMachineDeployments(b.Shoot.Components.Extensions.Worker.MachineDeployments())

		maxNodesTotal, err := b.CalculateMaxNodesTotal(b.Shoot.GetInfo())
		if err != nil {
			return err
		}
		b.Shoot.Components.ControlPlane.ClusterAutoscaler.SetMaxNodesTotal(maxNodesTotal)

		return b.Shoot.Components.ControlPlane.ClusterAutoscaler.Deploy(ctx)
	}

	return b.Shoot.Components.ControlPlane.ClusterAutoscaler.Destroy(ctx)
}

// ScaleClusterAutoscalerToZero scales cluster-autoscaler replicas to zero.
func (b *Botanist) ScaleClusterAutoscalerToZero(ctx context.Context) error {
	return client.IgnoreNotFound(kubernetesutils.ScaleDeployment(ctx, b.SeedClientSet.Client(), client.ObjectKey{Namespace: b.Shoot.ControlPlaneNamespace, Name: v1beta1constants.DeploymentNameClusterAutoscaler}, 0))
}

// CalculateMaxNodesTotal returns the maximum number of nodes the shoot can have based on the shoot networks and
// the limit configured in the CloudProfile. It returns 0 if there is no limitation.
func (b *Botanist) CalculateMaxNodesTotal(shoot *gardencorev1beta1.Shoot) (int64, error) {
	maxNetworks, err := b.CalculateMaxNodesForShootNetworks(shoot)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate max nodes for shoot networks: %w", err)
	}

	var maxLimit int64
	if limits := b.Shoot.CloudProfile.Spec.Limits; limits != nil && limits.MaxNodesTotal != nil {
		maxLimit = int64(*limits.MaxNodesTotal)
	}

	return utils.MinGreaterThanZero(maxNetworks, maxLimit), nil
}

// CalculateMaxNodesForShootNetworks returns the maximum number of nodes the shoot networks supports or 0 if there is no limitation.
func (b *Botanist) CalculateMaxNodesForShootNetworks(shoot *gardencorev1beta1.Shoot) (int64, error) {
	if shoot.Spec.Networking == nil || len(b.Shoot.Networks.Pods) == 0 {
		return 0, nil
	}
	maxNodesForPodsNetwork, err := b.calculateMaxNodesForPodsNetwork(shoot)
	if err != nil {
		return 0, err
	}
	maxNodesForNodesNetwork, err := b.calculateMaxNodesForNodesNetwork()
	if err != nil {
		return 0, err
	}

	return utils.MinGreaterThanZero(maxNodesForPodsNetwork, maxNodesForNodesNetwork), nil
}

func (b *Botanist) calculateMaxNodesForPodsNetwork(shoot *gardencorev1beta1.Shoot) (int64, error) {
	resultPerIPFamily := map[gardencorev1beta1.IPFamily]int64{}
	for _, podNetwork := range b.Shoot.Networks.Pods {
		podCIDRMaskSize, _ := podNetwork.Mask.Size()
		if podCIDRMaskSize == 0 {
			return 0, fmt.Errorf("pod CIDR is not in its canonical form")
		}
		// Calculate how many subnets with nodeCIDRMaskSize can be allocated out of the pod network (with podCIDRMaskSize).
		// This indicates how many Nodes we can host at max from a networking perspective.
		var maxNodeCount = &big.Int{}
		// For dual-stack, we use 80 as nodeCIDRMaskSize for IPv6. In general, for ipv6 nodeCIDRMaskSize and podCIDRMaskSize are dependent on the infrastructure provider.
		// For AWS, it is nodeCIDRMaskSize 80 and podCIDRMaskSize 56, for GCP nodeCIDRMaskSize 112 and podCIDRMaskSize 64.
		// With 80 as node nodeCIDRMaskSize in this calculation, IPv6 is not a limitation for the number of nodes.
		exp := 80 - int64(podCIDRMaskSize)
		if podNetwork.IP.To4() != nil || gardencorev1beta1.IsIPv6SingleStack(shoot.Spec.Networking.IPFamilies) {
			exp = int64(*shoot.Spec.Kubernetes.KubeControllerManager.NodeCIDRMaskSize) - int64(podCIDRMaskSize)
		}
		// Bigger numbers than 2^62 do not fit into an int64 variable and big.Int{}.Int64() is undefined in such cases.
		// The pod network is no limitation in this case anyway.
		if exp > 62 {
			maxNodeCount = big.NewInt(math.MaxInt64)
		} else {
			maxNodeCount.Exp(big.NewInt(2), big.NewInt(exp), nil)
		}

		if podNetwork.IP.To4() != nil {
			resultPerIPFamily[gardencorev1beta1.IPFamilyIPv4] += maxNodeCount.Int64()
		} else {
			resultPerIPFamily[gardencorev1beta1.IPFamilyIPv6] += maxNodeCount.Int64()
		}
	}

	// In a dual-stack scenario, return the minimum because beyond the minimum dual-stack is no longer possible.
	var result int64 = math.MaxInt64
	for _, value := range resultPerIPFamily {
		result = min(result, value)
	}
	return result, nil
}

func (b *Botanist) calculateMaxNodesForNodesNetwork() (int64, error) {
	if len(b.Shoot.Networks.Nodes) == 0 {
		return 0, nil
	}

	resultPerIPFamily := map[gardencorev1beta1.IPFamily]int64{}
	for _, nodeNetwork := range b.Shoot.Networks.Nodes {
		nodeCIDRMaskSize, _ := nodeNetwork.Mask.Size()
		if nodeCIDRMaskSize == 0 {
			return 0, fmt.Errorf("node CIDR is not in its canonical form")
		}
		ipCIDRMaskSize := int64(128)
		if nodeNetwork.IP.To4() != nil {
			ipCIDRMaskSize = int64(32)
		}
		// Calculate how many "single IP" subnets fit into the node network
		var maxNodeCount = &big.Int{}
		exp := ipCIDRMaskSize - int64(nodeCIDRMaskSize)
		// Bigger numbers than 2^62 do not fit into an int64 variable and big.Int{}.Int64() is undefined in such cases.
		// The node network is no limitation in this case anyway.
		if exp > 62 {
			maxNodeCount = big.NewInt(math.MaxInt64)
		} else {
			maxNodeCount.Exp(big.NewInt(2), big.NewInt(exp), nil)
		}

		if nodeNetwork.IP.To4() != nil {
			// Subtract the broadcast addresses
			maxNodeCount.Sub(maxNodeCount, big.NewInt(2))
			resultPerIPFamily[gardencorev1beta1.IPFamilyIPv4] += maxNodeCount.Int64()
		} else {
			resultPerIPFamily[gardencorev1beta1.IPFamilyIPv6] += maxNodeCount.Int64()
		}
	}

	// In a dual-stack scenario, return the minimum because beyond the minimum dual-stack is no longer possible.
	var result int64 = math.MaxInt64
	for _, value := range resultPerIPFamily {
		result = min(result, value)
	}
	return result, nil
}
