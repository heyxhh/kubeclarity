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
	"os"
	"os/exec"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/openclarity/kubeclarity/e2e/common"
)

func TestCLIScan(t *testing.T) {
	stopCh := make(chan struct{})
	//defer func() {
	//	stopCh <- struct{}{}
	//	time.Sleep(2 * time.Second)
	//}()
	assert.NilError(t, setupCLIScanTestEnv(stopCh))

	assert.NilError(t, startCLIScan(t))
	// wait for progress DONE
	// assert.NilError(t, waitForScanDone())

	f1 := features.New("assert results").
		WithLabel("type", "assert").
		Assess("vulnerability in DB", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			common.AssertGetRuntimeScanResults(t, kubeclarityAPI)
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

// analyze dir with gomod and syft  - output sbom
// analyze image with syft and merge sbom - output sbom
// check sbom output is merged

// vul scan - on merged sbom - check db
// vul scan on image

func startCLIScan(t *testing.T) error {
	assert.NilError(t, os.Setenv("BACKEND_HOST", "localhost:"+common.KubeClarityPortForwardHostPort))
	assert.NilError(t, os.Setenv("BACKEND_DISABLE_TLS", "true"))
	assert.NilError(t, os.Setenv("ANALYZER_LIST", "syft")) // TODO do we want to use all the analyzers?
	cmd := exec.Command("kubeclarity-cli", "analyze", "-o", "test.sbom")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute command. %v, %s", err, out)
	}
	// analyze - use all supported analyzers?
	// scan - use all supported scanners?
	// export all results to kubeclarity backend (in both stages)
}

//func waitForScanDone() error {
//	timer := time.NewTimer(3 * time.Minute)
//	ticker := time.NewTicker(3 * time.Second)
//	for {
//		select {
//		case <-timer.C:
//			return fmt.Errorf("timeout reached")
//		case <-ticker.C:
//			params := operations.NewGetRuntimeScanProgressParams()
//			res, err := kubeclarityAPI.Operations.GetRuntimeScanProgress(params)
//			if err != nil {
//				return err
//			}
//			if res.Payload.Status == models.RuntimeScanStatusDONE {
//				return nil
//			}
//		}
//	}
//}

func setupCLIScanTestEnv(stopCh chan struct{}) error {
	println("Set up cli scan test env...")

	helmManager := helm.New(KubeconfigFile)

	println("creating namespace test...")
	if err := common.CreateNamespace(k8sClient, "test"); err != nil {
		return fmt.Errorf("failed to create test namepsace: %v", err)
	}

	println("deploying test image to test namespace...")
	if err := common.InstallTest("test"); err != nil {
		return fmt.Errorf("failed to install test image: %v", err)
	}

	println("deploying kubeclarity...")
	if err := common.InstallKubeClarity(helmManager, "--create-namespace --wait"); err != nil {
		return fmt.Errorf("failed to install kubeclarity: %v", err)
	}

	println("waiting for kubeclarity to run...")
	if err := common.WaitForKubeClarityPodRunning(k8sClient); err != nil {
		common.DescribeKubeClarityDeployment()
		common.DescribeKubeClarityPods()
		return fmt.Errorf("failed to wait for kubeclarity pod to be running: %v", err)
	}

	println("port-forward to kubeclarity...")
	common.PortForwardToKubeClarity(stopCh)

	return nil
}
