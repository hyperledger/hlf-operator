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

// FakeFabricMainChannels implements FabricMainChannelInterface
type FakeFabricMainChannels struct {
	Fake *FakeHlfV1alpha1
}

var fabricmainchannelsResource = v1alpha1.SchemeGroupVersion.WithResource("fabricmainchannels")

var fabricmainchannelsKind = v1alpha1.SchemeGroupVersion.WithKind("FabricMainChannel")

// Get takes name of the fabricMainChannel, and returns the corresponding fabricMainChannel object, and an error if there is any.
func (c *FakeFabricMainChannels) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FabricMainChannel, err error) {
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(fabricmainchannelsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// List takes label and field selectors, and returns the list of FabricMainChannels that match those selectors.
func (c *FakeFabricMainChannels) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FabricMainChannelList, err error) {
	emptyResult := &v1alpha1.FabricMainChannelList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(fabricmainchannelsResource, fabricmainchannelsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.FabricMainChannelList{ListMeta: obj.(*v1alpha1.FabricMainChannelList).ListMeta}
	for _, item := range obj.(*v1alpha1.FabricMainChannelList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested fabricMainChannels.
func (c *FakeFabricMainChannels) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(fabricmainchannelsResource, opts))
}

// Create takes the representation of a fabricMainChannel and creates it.  Returns the server's representation of the fabricMainChannel, and an error, if there is any.
func (c *FakeFabricMainChannels) Create(ctx context.Context, fabricMainChannel *v1alpha1.FabricMainChannel, opts v1.CreateOptions) (result *v1alpha1.FabricMainChannel, err error) {
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(fabricmainchannelsResource, fabricMainChannel, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// Update takes the representation of a fabricMainChannel and updates it. Returns the server's representation of the fabricMainChannel, and an error, if there is any.
func (c *FakeFabricMainChannels) Update(ctx context.Context, fabricMainChannel *v1alpha1.FabricMainChannel, opts v1.UpdateOptions) (result *v1alpha1.FabricMainChannel, err error) {
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(fabricmainchannelsResource, fabricMainChannel, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeFabricMainChannels) UpdateStatus(ctx context.Context, fabricMainChannel *v1alpha1.FabricMainChannel, opts v1.UpdateOptions) (result *v1alpha1.FabricMainChannel, err error) {
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(fabricmainchannelsResource, "status", fabricMainChannel, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// Delete takes name of the fabricMainChannel and deletes it. Returns an error if one occurs.
func (c *FakeFabricMainChannels) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(fabricmainchannelsResource, name, opts), &v1alpha1.FabricMainChannel{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeFabricMainChannels) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(fabricmainchannelsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.FabricMainChannelList{})
	return err
}

// Patch applies the patch and returns the patched fabricMainChannel.
func (c *FakeFabricMainChannels) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricMainChannel, err error) {
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricmainchannelsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied fabricMainChannel.
func (c *FakeFabricMainChannels) Apply(ctx context.Context, fabricMainChannel *hlfkungfusoftwareesv1alpha1.FabricMainChannelApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricMainChannel, err error) {
	if fabricMainChannel == nil {
		return nil, fmt.Errorf("fabricMainChannel provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricMainChannel)
	if err != nil {
		return nil, err
	}
	name := fabricMainChannel.Name
	if name == nil {
		return nil, fmt.Errorf("fabricMainChannel.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricmainchannelsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeFabricMainChannels) ApplyStatus(ctx context.Context, fabricMainChannel *hlfkungfusoftwareesv1alpha1.FabricMainChannelApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricMainChannel, err error) {
	if fabricMainChannel == nil {
		return nil, fmt.Errorf("fabricMainChannel provided to Apply must not be nil")
	}
	data, err := json.Marshal(fabricMainChannel)
	if err != nil {
		return nil, err
	}
	name := fabricMainChannel.Name
	if name == nil {
		return nil, fmt.Errorf("fabricMainChannel.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.FabricMainChannel{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(fabricmainchannelsResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.FabricMainChannel), err
}
