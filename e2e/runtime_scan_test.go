// Copyright © 2021 Cisco Systems, Inc. and its affiliates.
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

package e2e

import (
	"context"
	"fmt"
	"gotest.tools/assert"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/openclarity/kubeclarity/api/client/client/operations"
	"github.com/openclarity/kubeclarity/api/client/models"
	"github.com/openclarity/kubeclarity/e2e/utils"
)

var want = &models.RuntimeScanResults{
	CisDockerBenchmarkCountPerLevel: nil,
	CisDockerBenchmarkCounters: &models.CISDockerBenchmarkScanCounters{
		Applications: 0,
		Resources:    0,
	},
	CisDockerBenchmarkScanEnabled: false,
	Counters: &models.RuntimeScanCounters{
		Applications:    1,
		Packages:        6,
		Resources:       1,
		Vulnerabilities: 28,
	},
	Failures:                 []*models.RuntimeScanFailure{

		// TODO why no failures?
	},
	VulnerabilityPerSeverity: []*models.VulnerabilityCount{
		{
			Count:    10,
			Severity: models.VulnerabilitySeverityHIGH,
		},
		{
			Count:    15,
			Severity: models.VulnerabilitySeverityMEDIUM,
		},
		{
			Count:    1,
			Severity: models.VulnerabilitySeverityLOW,
		},
		{
			Count:    2,
			Severity: models.VulnerabilitySeverityCRITICAL,
		},
	},
}

func TestRuntimeScan(t *testing.T) {
	stopCh := make(chan struct{})
	//defer func() {
	//	stopCh <- struct{}{}
	//	time.Sleep(2 * time.Second)
	//}()
	assert.NilError(t, setupRuntimeScanTestEnv(stopCh))

	assert.NilError(t, startRuntimeScan([]string{"test"}))
	// wait for progress DONE
	assert.NilError(t, waitForScanDone())

	f1 := features.New("assert results").
		WithLabel("type", "assert").
		Assess("vulnerability in DB", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			utils.AssertGetRuntimeScanResults(t, kubeclarityAPI, want)
			return ctx
		}).Feature()

	//f2 := features.New("spec").
	//	WithLabel("type", "spec").
	//	Assess("spec exist in DB", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	//		utils.AssertGetAPIInventory(t, kubeclarityAPI, wantGetAPIInventoryOKBody)
	//		return ctx
	//	}).Feature()

	// test features
	testenv.Test(t, f1)
}

func startRuntimeScan(namespaces []string) error {
	params := operations.NewPutRuntimeScanStartParams().WithBody(&models.RuntimeScanConfig{
		Namespaces: namespaces,
	})
	_, err := kubeclarityAPI.Operations.PutRuntimeScanStart(params)
	return err
}

func waitForScanDone() error {
	timer := time.NewTimer(3 * time.Minute)
	ticker := time.NewTicker(3 * time.Second)
	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timeout reached")
		case <-ticker.C:
			params := operations.NewGetRuntimeScanProgressParams()
			res, err := kubeclarityAPI.Operations.GetRuntimeScanProgress(params)
			if err != nil {
				return err
			}
			if res.Payload.Status == models.RuntimeScanStatusDONE {
				return nil
			}
		}
	}
}

func setupRuntimeScanTestEnv(stopCh chan struct{}) error {
	println("Set up runtime scan test env...")

	helmManager := helm.New(KubeconfigFile)

	println("creating namespace test...")
	envfuncs.CreateNamespace("test")

	println("deploying curl to test namespace...")
	if err := utils.InstallCurl("test"); err != nil {
		return fmt.Errorf("failed to install curl: %v", err)
	}

	println("deploying kubeclarity...")
	if err := utils.InstallKubeClarity(helmManager, "--create-namespace --wait'"); err != nil {
		return fmt.Errorf("failed to install kubeclarity: %v", err)
	}

	println("waiting for kubeclarity to run...")
	if err := utils.WaitForKubeClarityPodRunning(k8sClient); err != nil {
		utils.DescribeKubeClarityDeployment()
		utils.DescribeKubeClarityPods()
		return fmt.Errorf("failed to wait for kubeclarity pod to be running: %v", err)
	}

	println("port-forward to kubeclarity...")
	utils.PortForwardToKubeClarity(stopCh)

	return nil
}
