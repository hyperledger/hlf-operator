/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/minio/operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeFabricChaincodeCommits implements FabricChaincodeCommitInterface
type FakeFabricChaincodeCommits struct {
	Fake *FakeHlfV1alpha1
}

var fabricchaincodecommitsResource = v1alpha1.SchemeGroupVersion.WithResource("fabricchaincodecommits")

var fabricchaincodecommitsKind = v1alpha1.SchemeGroupVersion.WithKind("FabricChaincodeCommit")

// Get takes name of the fabricChaincodeCommit, and returns the corresponding fabricChaincodeCommit object, and an error if there is any.
func (c *FakeFabricChaincodeCommits) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(fabricchaincodecommitsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// List takes label and field selectors, and returns the list of FabricChaincodeCommits that match those selectors.
func (c *FakeFabricChaincodeCommits) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricChaincodeCommitList, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommitList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(fabricchaincodecommitsResource, fabricchaincodecommitsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.FabricChaincodeCommitList{ListMeta: obj.(*v1alpha1.FabricChaincodeCommitList).ListMeta}
	for _, item := range obj.(*v1alpha1.FabricChaincodeCommitList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested fabricChaincodeCommits.
func (c *FakeFabricChaincodeCommits) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(fabricchaincodecommitsResource, opts))
}

// Create takes the representation of a fabricChaincodeCommit and creates it.  Returns the server's representation of the fabricChaincodeCommit, and an error, if there is any.
func (c *FakeFabricChaincodeCommits) Create(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.CreateOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(fabricchaincodecommitsResource, fabricChaincodeCommit, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// Update takes the representation of a fabricChaincodeCommit and updates it. Returns the server's representation of the fabricChaincodeCommit, and an error, if there is any.
func (c *FakeFabricChaincodeCommits) Update(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.UpdateOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(fabricchaincodecommitsResource, fabricChaincodeCommit, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeFabricChaincodeCommits) UpdateStatus(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.UpdateOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(fabricchaincodecommitsResource, "status", fabricChaincodeCommit, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// Delete takes name of the fabricChaincodeCommit and deletes it. Returns an error if one occurs.
func (c *FakeFabricChaincodeCommits) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(fabricchaincodecommitsResource, name, opts), &v1alpha1.FabricChaincodeCommit{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeFabricChaincodeCommits) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(fabricchaincodecommitsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.FabricChaincodeCommitList{})
	return err
}

// Patch applies the patch and returns the patched fabricChaincodeCommit.
func (c *FakeFabricChaincodeCommits) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricChaincodeCommit, err error) {
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricchaincodecommitsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricChaincodeCommit.
func (c *FakeFabricChaincodeCommits) Apply(ctx context.Context, fabricChaincodeCommit *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	if fabricChaincodeCommit == nil {
		return nil, fmt.Errorf("fabricChaincodeCommit provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricChaincodeCommit)
	if err != nil {
		return nil, err
	}
	name := fabricChaincodeCommit.Name
	if name == nil {
		return nil, fmt.Errorf("fabricChaincodeCommit.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricchaincodecommitsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeFabricChaincodeCommits) ApplyStatus(ctx context.Context, fabricChaincodeCommit *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincodeCommit, err error) {
	if fabricChaincodeCommit == nil {
		return nil, fmt.Errorf("fabricChaincodeCommit provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricChaincodeCommit)
	if err != nil {
		return nil, err
	}
	name := fabricChaincodeCommit.Name
	if name == nil {
		return nil, fmt.Errorf("fabricChaincodeCommit.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.FabricChaincodeCommit{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricchaincodecommitsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricChaincodeCommit), err
}
