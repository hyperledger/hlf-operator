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

// FabricOperatorAPIsGetter has a method to return a FabricOperatorAPIInterface.
// A group's client should implement this interface.
type FabricOperatorAPIsGetter interface {
	FabricOperatorAPIs(namespace string) FabricOperatorAPIInterface
}

// FabricOperatorAPIInterface has methods to work with FabricOperatorAPI resources.
type FabricOperatorAPIInterface interface {
	Create(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.CreateOptions) (*v1alpha1.FabricOperatorAPI, error)
	Update(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.UpdateOptions) (*v1alpha1.FabricOperatorAPI, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, fabricOperatorAPI *v1alpha1.FabricOperatorAPI, opts v1.UpdateOptions) (*v1alpha1.FabricOperatorAPI, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricOperatorAPI, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricOperatorAPIList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricOperatorAPI, err error)
	Apply(ctx context.Context, fabricOperatorAPI *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOperatorAPI, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, fabricOperatorAPI *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricOperatorAPI, err error)
	FabricOperatorAPIExpansion
}

// fabricOperatorAPIs implements FabricOperatorAPIInterface
type fabricOperatorAPIs struct {
	*gentype.ClientWithListAndApply[*v1alpha1.FabricOperatorAPI, *v1alpha1.FabricOperatorAPIList, *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration]
}

// newFabricOperatorAPIs returns a FabricOperatorAPIs
func newFabricOperatorAPIs(c *HlfV1alpha1Client, namespace string) *fabricOperatorAPIs {
	return &fabricOperatorAPIs{
		gentype.NewClientWithListAndApply[*v1alpha1.FabricOperatorAPI, *v1alpha1.FabricOperatorAPIList, *hlfkungfusoftwareesv1alpha1.FabricOperatorAPIApplyConfiguration](
			"fabricoperatorapis",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1alpha1.FabricOperatorAPI { return &v1alpha1.FabricOperatorAPI{} },
			func() *v1alpha1.FabricOperatorAPIList { return &v1alpha1.FabricOperatorAPIList{} }),
	}
}
