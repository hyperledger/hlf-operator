/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// FabricChaincodeInstallLister helps list FabricChaincodeInstalls.
// All objects returned here must be treated as read-only.
type FabricChaincodeInstallLister interface {
	// List lists all FabricChaincodeInstalls in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.FabricChaincodeInstall, err error)
	// Get retrieves the FabricChaincodeInstall from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.FabricChaincodeInstall, error)
	FabricChaincodeInstallListerExpansion
}

// fabricChaincodeInstallLister implements the FabricChaincodeInstallLister interface.
type fabricChaincodeInstallLister struct {
	listers.ResourceIndexer[*v1alpha1.FabricChaincodeInstall]
}

// NewFabricChaincodeInstallLister returns a new FabricChaincodeInstallLister.
func NewFabricChaincodeInstallLister(indexer cache.Indexer) FabricChaincodeInstallLister {
	return &fabricChaincodeInstallLister{listers.New[*v1alpha1.FabricChaincodeInstall](indexer, v1alpha1.Resource("fabricchaincodeinstall"))}
}
