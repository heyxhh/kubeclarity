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

package common

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	v1 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

// EXPORTED:

func InstallTest(ns string) error {
	cmd := exec.Command("kubectl", "-n", ns, "apply", "-f", "test.yaml")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute command. %v, %s", err, out)
	}
	return nil
}

func LoadDockerImagesToCluster(cluster, tag string) error {
	if err := LoadDockerImageToCluster(cluster, fmt.Sprintf("ghcr.io/openclarity/kubeclarity:%v", tag)); err != nil {
		return fmt.Errorf("failed to load docker image to cluster: %v", err)
	}
	if err := LoadDockerImageToCluster(cluster, fmt.Sprintf("ghcr.io/openclarity/kubeclarity-sbom-db:%v", tag)); err != nil {
		return fmt.Errorf("failed to load docker image to cluster: %v", err)
	}
	// ghcr.io/openclarity/kubeclarity-cli
	if err := LoadDockerImageToCluster(cluster, fmt.Sprintf("ghcr.io/openclarity/kubeclarity-runtime-k8s-scanner:%v", tag)); err != nil {
		return fmt.Errorf("failed to load docker image to cluster: %v", err)
	}
	if err := LoadDockerImageToCluster(cluster, fmt.Sprintf("ghcr.io/openclarity/kubeclarity-cis-docker-benchmark-scanner:%v", tag)); err != nil {
		return fmt.Errorf("failed to load docker image to cluster: %v", err)
	}

	return nil
}

func LoadDockerImageToCluster(cluster, image string) error {
	cmd := exec.Command("kind", "load", "docker-image", image, "--name", cluster)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute command. %v, %s", err, out)
	}
	return nil
}

var curDir, _ = os.Getwd()
var chartPath = filepath.Join(curDir, "../charts/kubeclarity")

func InstallKubeClarity(manager *helm.Manager, args string) error {
	if err := manager.RunInstall(helm.WithName(KubeClarityHelmReleaseName),
		helm.WithVersion("v1.1"),
		helm.WithNamespace(KubeClarityNamespace),
		helm.WithChart(chartPath),
		helm.WithArgs(args)); err != nil {
		return fmt.Errorf("failed to run helm install command with args: %v. %v", args, err)
	}
	return nil
}

func PortForwardToKubeClarity(stopCh chan struct{}) {
	// TODO make it better
	go func() {
		err, out := portForward("service", KubeClarityNamespace, KubeClarityServiceName, KubeClarityPortForwardHostPort, KubeClarityPortForwardTargetPort, stopCh)
		if err != nil {
			fmt.Printf("port forward failed. %s. %v", out, err)
			return
		}
	}()
	time.Sleep(3 * time.Second)
}

func BoolPtr(val bool) *bool {
	ret := val
	return &ret
}

func Int64Ptr(val int64) *int64 {
	ret := val
	return &ret
}

//TODO use https://github.com/kubernetes-sigs/e2e-framework/tree/main/examples/wait_for_resources
func WaitForKubeClarityPodRunning(client klient.Client) error {
	podList := v1.PodList{}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(3 * time.Minute)
	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout reached")
		case <-ticker.C:
			if err := client.Resources(KubeClarityNamespace).List(context.TODO(), &podList, func(lo *v12.ListOptions) {
				lo.LabelSelector = "app=kubeclarity-kubeclarity"
			}); err != nil {
				return fmt.Errorf("failed to get pod kubeclarity. %v", err)
			}
			pod := podList.Items[0]
			if pod.Status.Phase == v1.PodRunning {
				return nil
			}
		}
	}
}

// NON EXPORTED:

func portForward(kind, namespace, name, hostPort, targetPort string, stopCh chan struct{}) (error, []byte) {
	cmd := exec.Command("kubectl", "port-forward", "-n", namespace,
		fmt.Sprintf("%s/%s", kind, name), fmt.Sprintf("%s:%s", hostPort, targetPort))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return err, out
	}
	return nil, nil
}
