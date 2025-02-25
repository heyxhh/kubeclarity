// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"github.com/openclarity/kubeclarity/api/server/models"
	runtime_scan_models "github.com/openclarity/kubeclarity/runtime_scan/api/server/models"
)

type ResourceInfo struct {

	// resource hash
	ResourceHash string `json:"resourceHash,omitempty"`

	// resource name
	ResourceName string `json:"resourceName,omitempty"`

	// resource type
	ResourceType ResourceType `json:"resourceType,omitempty"`
}

func ResourceInfoFromRuntimeScan(in *runtime_scan_models.ResourceInfo) *ResourceInfo {
	return &ResourceInfo{
		ResourceHash: in.ResourceHash,
		ResourceName: in.ResourceName,
		ResourceType: ResourceType(in.ResourceType),
	}
}

func ResourceInfoFromBackendAPI(in *models.ResourceInfo) *ResourceInfo {
	return &ResourceInfo{
		ResourceHash: in.ResourceHash,
		ResourceName: in.ResourceName,
		ResourceType: ResourceType(in.ResourceType),
	}
}
