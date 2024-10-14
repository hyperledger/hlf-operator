/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/minio/operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	scheme "github.com/minio/operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// FabricCAsGetter has a method to return a FabricCAInterface.
// A group's client should implement this interface.
type FabricCAsGetter interface {
	FabricCAs(namespace string) FabricCAInterface
}

// FabricCAInterface has methods to work with FabricCA resources.
type FabricCAInterface interface {
	Create(ctx context.Context, fabricCA *v1alpha1.FabricCA, opts v1.CreateOptions) (*v1alpha1.FabricCA, error)
	Update(ctx context.Context, fabricCA *v1alpha1.FabricCA, opts v1.UpdateOptions) (*v1alpha1.FabricCA, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, fabricCA *v1alpha1.FabricCA, opts v1.UpdateOptions) (*v1alpha1.FabricCA, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricCA, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricCAList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricCA, err error)
	Apply(ctx context.Context, fabricCA *hlfkungfusoftwareesv1alpha1.FabricCAApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricCA, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, fabricCA *hlfkungfusoftwareesv1alpha1.FabricCAApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricCA, err error)
	FabricCAExpansion
}

// fabricCAs implements FabricCAInterface
type fabricCAs struct {
	*gentype.ClientWithListAndApply[*v1alpha1.FabricCA, *v1alpha1.FabricCAList, *hlfkungfusoftwareesv1alpha1.FabricCAApplyConfiguration]
}

// newFabricCAs returns a FabricCAs
func newFabricCAs(c *HlfV1alpha1Client, namespace string) *fabricCAs {
	return &fabricCAs{
		gentype.NewClientWithListAndApply[*v1alpha1.FabricCA, *v1alpha1.FabricCAList, *hlfkungfusoftwareesv1alpha1.FabricCAApplyConfiguration](
			"fabriccas",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1alpha1.FabricCA { return &v1alpha1.FabricCA{} },
			func() *v1alpha1.FabricCAList { return &v1alpha1.FabricCAList{} }),
	}
}
