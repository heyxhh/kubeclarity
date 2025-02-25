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

package scanner

import (
	"testing"

	"github.com/ghodss/yaml"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	_config "github.com/openclarity/kubeclarity/runtime_scan/pkg/config"
	_creds "github.com/openclarity/kubeclarity/runtime_scan/pkg/scanner/creds"
	"github.com/openclarity/kubeclarity/runtime_scan/pkg/types"
	shared "github.com/openclarity/kubeclarity/shared/pkg/config"
)

func Test_getSimpleImageName(t *testing.T) {
	type args struct {
		imageName string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "valid image name with tag and repo",
			args: args{
				imageName: "docker.io/nginx:1.10",
			},
			want: "nginx",
		},
		{
			name: "valid image name with digest with repo",
			args: args{
				imageName: "docker.io/nginx@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2",
			},
			want: "nginx",
		},
		{
			name: "valid image name with digest no repo",
			args: args{
				imageName: "nginx@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2",
			},
			want: "nginx",
		},
		{
			name: "no tag",
			args: args{
				imageName: "docker.io/nginx",
			},
			want: "nginx",
		},
		{
			name: "no tag with port",
			args: args{
				imageName: "docker.io:8080/nginx",
			},
			want: "nginx",
		},
		{
			name: "repo with port",
			args: args{
				imageName: "docker.io:8080/nginx:1.10",
			},
			want: "nginx",
		},
		{
			name: "no repo no tag",
			args: args{
				imageName: "nginx",
			},
			want: "nginx",
		},
		{
			name: "valid image name with digest with repo with tag",
			args: args{
				imageName: "solsson/kafka:2.2.1@sha256:450c6fdacae3f89ca28cecb36b2f120aad9b19583d68c411d551502ee8d0b09b",
			},
			want: "kafka",
		},
		{
			name: "name ends with '/' - invalid reference format",
			args: args{
				imageName: "docker.io:8080/not/valid/:222",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSimpleImageName(tt.args.imageName)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSimpleImageName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSimpleImageName() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createJobName(t *testing.T) {
	type args struct {
		imageName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "trim right '-' that left from the uuid after name was truncated due to max len",
			args: args{
				imageName: "stackdriver-logging-agent",
			},
		},
		{
			name: "underscore",
			args: args{
				imageName: "under_score",
			},
		},
		{
			name: "invalid image name",
			args: args{
				imageName: "InvAliD",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createJobName(tt.args.imageName)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("createJobName() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			errs := validation.IsDNS1123Label(got)
			if len(errs) != 0 {
				t.Errorf("createJobName() = name is not valid. got=%v, errs=%+v", got, errs)
			}
		})
	}
}

func Test_setJobScanUUID(t *testing.T) {
	type args struct {
		job      *batchv1.Job
		scanUUID string
	}
	tests := []struct {
		name        string
		args        args
		expectedJob *batchv1.Job
	}{
		{
			name: "empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{},
									{},
								},
							},
						},
					},
				},
				scanUUID: "scanUUID",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{Name: "SCAN_UUID", Value: "scanUUID"},
									},
								},
								{
									Env: []corev1.EnvVar{
										{Name: "SCAN_UUID", Value: "scanUUID"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "non empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Env: []corev1.EnvVar{
											{Name: "ENV1", Value: "123"},
										},
									},
									{
										Env: []corev1.EnvVar{
											{Name: "ENV2", Value: "456"},
										},
									},
								},
							},
						},
					},
				},
				scanUUID: "scanUUID",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{Name: "ENV1", Value: "123"},
										{Name: "SCAN_UUID", Value: "scanUUID"},
									},
								},
								{
									Env: []corev1.EnvVar{
										{Name: "ENV2", Value: "456"},
										{Name: "SCAN_UUID", Value: "scanUUID"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setJobScanUUID(tt.args.job, tt.args.scanUUID)
			assert.DeepEqual(t, tt.args.job, tt.expectedJob)
		})
	}
}

func Test_setJobImageIDToScan(t *testing.T) {
	type args struct {
		job     *batchv1.Job
		imageID string
	}
	tests := []struct {
		name        string
		args        args
		expectedJob *batchv1.Job
	}{
		{
			name: "empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{},
									{},
								},
							},
						},
					},
				},
				imageID: "imageID",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{Name: shared.ImageIDToScan, Value: "imageID"},
									},
								},
								{
									Env: []corev1.EnvVar{
										{Name: shared.ImageIDToScan, Value: "imageID"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "non empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Env: []corev1.EnvVar{
											{Name: "ENV1", Value: "123"},
										},
									},
									{
										Env: []corev1.EnvVar{
											{Name: "ENV2", Value: "456"},
										},
									},
								},
							},
						},
					},
				},
				imageID: "imageID",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{Name: "ENV1", Value: "123"},
										{Name: shared.ImageIDToScan, Value: "imageID"},
									},
								},
								{
									Env: []corev1.EnvVar{
										{Name: "ENV2", Value: "456"},
										{Name: shared.ImageIDToScan, Value: "imageID"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setJobImageIDToScan(tt.args.job, tt.args.imageID)
			assert.DeepEqual(t, tt.args.job, tt.expectedJob)
		})
	}
}

func Test_setJobImagePullSecret(t *testing.T) {
	type args struct {
		job        *batchv1.Job
		secretName string
	}
	tests := []struct {
		name        string
		args        args
		expectedJob *batchv1.Job
	}{
		{
			name: "empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{},
									{},
								},
							},
						},
					},
				},
				secretName: "secretName",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{
											Name: "K8S_IMAGE_PULL_SECRET", ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "secretName",
													},
													Key: corev1.DockerConfigJsonKey,
												},
											},
										},
									},
								},
								{
									Env: []corev1.EnvVar{
										{
											Name: "K8S_IMAGE_PULL_SECRET", ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "secretName",
													},
													Key: corev1.DockerConfigJsonKey,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "non empty env list",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Env: []corev1.EnvVar{
											{Name: "ENV1", Value: "123"},
										},
									},
									{
										Env: []corev1.EnvVar{
											{Name: "ENV2", Value: "456"},
										},
									},
								},
							},
						},
					},
				},
				secretName: "secretName",
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Env: []corev1.EnvVar{
										{Name: "ENV1", Value: "123"},
										{
											Name: "K8S_IMAGE_PULL_SECRET", ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "secretName",
													},
													Key: corev1.DockerConfigJsonKey,
												},
											},
										},
									},
								},
								{
									Env: []corev1.EnvVar{
										{Name: "ENV2", Value: "456"},
										{
											Name: "K8S_IMAGE_PULL_SECRET", ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "secretName",
													},
													Key: corev1.DockerConfigJsonKey,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setJobImagePullSecret(tt.args.job, tt.args.secretName)
			assert.DeepEqual(t, tt.args.job, tt.expectedJob)
		})
	}
}

func Test_removeCISDockerBenchmarkScannerFromJob(t *testing.T) {
	type args struct {
		job *batchv1.Job
	}
	tests := []struct {
		name        string
		args        args
		expectedJob *batchv1.Job
	}{
		{
			name: "cisDockerBenchmarkScannerContainerName first",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: cisDockerBenchmarkScannerContainerName,
									},
									{
										Name: "test",
									},
								},
							},
						},
					},
				},
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "cisDockerBenchmarkScannerContainerName last",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
									{
										Name: cisDockerBenchmarkScannerContainerName,
									},
								},
							},
						},
					},
				},
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "cisDockerBenchmarkScannerContainerName middle",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
									{
										Name: cisDockerBenchmarkScannerContainerName,
									},
									{
										Name: "test2",
									},
								},
							},
						},
					},
				},
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
								{
									Name: "test2",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "cisDockerBenchmarkScannerContainerName is missing",
			args: args{
				job: &batchv1.Job{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "test",
									},
									{
										Name: "test2",
									},
								},
							},
						},
					},
				},
			},
			expectedJob: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "test",
								},
								{
									Name: "test2",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			removeCISDockerBenchmarkScannerFromJob(tt.args.job)
			assert.DeepEqual(t, tt.args.job, tt.expectedJob)
		})
	}
}

var testScannerJobTemplate = []byte(`apiVersion: batch/v1
kind: Job
metadata:
  labels:
    app: scanner
    sidecar.istio.io/inject: "false"
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
     labels:
      app: scanner
      sidecar.istio.io/inject: "false"
    spec:
      restartPolicy: Never
      containers:
      - name: vulnerability-scanner
        image: TBD
        args:
        - scan
        env:
        - name: REGISTRY_INSECURE
          value: "false"
        - name: RESULT_SERVICE_HOST
          value: kubeclarity.kubeclarity
        - name: RESULT_SERVICE_PORT
          value: 8888
        securityContext:
          capabilities:
            drop:
            - all
          runAsNonRoot: true
          runAsGroup: 1001
          runAsUser: 1001
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          requests:
           memory: "50Mi"
           cpu: "50m"
          limits:
            memory: "1000Mi"
            cpu: "1000m"
`)

var expectedScannerJobTemplate = []byte(`apiVersion: batch/v1
kind: Job
metadata:
  namespace: namespace
  labels:
    app: scanner
    sidecar.istio.io/inject: "false"
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
     labels:
      app: scanner
      sidecar.istio.io/inject: "false"
    spec:
      restartPolicy: Never
      containers:
      - name: vulnerability-scanner
        image: TBD
        args:
        - scan
        env:
        - name: REGISTRY_INSECURE
          value: "false"
        - name: RESULT_SERVICE_HOST
          value: kubeclarity.kubeclarity
        - name: RESULT_SERVICE_PORT
          value: 8888
        - name: SCAN_UUID
          value: "scanUUID"
        - name: IMAGE_ID_TO_SCAN
          value: "image-id"
        - name: IMAGE_HASH_TO_SCAN
          value: "image-hash"
        - name: IMAGE_NAME_TO_SCAN
          value: "image-name"
        securityContext:
          capabilities:
            drop:
            - all
          runAsNonRoot: true
          runAsGroup: 1001
          runAsUser: 1001
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          requests:
           memory: "50Mi"
           cpu: "50m"
          limits:
            memory: "1000Mi"
            cpu: "1000m"
`)

var expectedScannerJobTemplateWithImagePullSecret = []byte(`apiVersion: batch/v1
kind: Job
metadata:
  namespace: namespace
  labels:
    app: scanner
    sidecar.istio.io/inject: "false"
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
     labels:
      app: scanner
      sidecar.istio.io/inject: "false"
    spec:
      restartPolicy: Never
      containers:
      - name: vulnerability-scanner
        image: TBD
        args:
        - scan
        env:
        - name: REGISTRY_INSECURE
          value: "false"
        - name: RESULT_SERVICE_HOST
          value: kubeclarity.kubeclarity
        - name: RESULT_SERVICE_PORT
          value: 8888
        - name: SCAN_UUID
          value: "scanUUID"
        - name: IMAGE_ID_TO_SCAN
          value: "image-id"
        - name: IMAGE_HASH_TO_SCAN
          value: "image-hash"
        - name: IMAGE_NAME_TO_SCAN
          value: "image-name"
        - name: K8S_IMAGE_PULL_SECRET
          valueFrom:
            secretKeyRef:
              name: imagePullSecret
              key: ".dockerconfigjson"
        securityContext:
          capabilities:
            drop:
            - all
          runAsNonRoot: true
          runAsGroup: 1001
          runAsUser: 1001
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          requests:
           memory: "50Mi"
           cpu: "50m"
          limits:
            memory: "1000Mi"
            cpu: "1000m"
`)

var expectedScannerJobTemplateWithFakeCred = []byte(`apiVersion: batch/v1
kind: Job
metadata:
  namespace: namespace
  labels:
    app: scanner
    sidecar.istio.io/inject: "false"
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    metadata:
     labels:
      app: scanner
      sidecar.istio.io/inject: "false"
    spec:
      restartPolicy: Never
      containers:
      - name: vulnerability-scanner
        image: TBD
        args:
        - scan
        env:
        - name: REGISTRY_INSECURE
          value: "false"
        - name: RESULT_SERVICE_HOST
          value: kubeclarity.kubeclarity
        - name: RESULT_SERVICE_PORT
          value: 8888
        - name: SCAN_UUID
          value: "scanUUID"
        - name: IMAGE_ID_TO_SCAN
          value: "image-id"
        - name: IMAGE_HASH_TO_SCAN
          value: "image-hash"
        - name: IMAGE_NAME_TO_SCAN
          value: "image-name"
        - name: fake-cred-name
          value: fake-cred-value
        securityContext:
          capabilities:
            drop:
            - all
          runAsNonRoot: true
          runAsGroup: 1001
          runAsUser: 1001
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          requests:
           memory: "50Mi"
           cpu: "50m"
          limits:
            memory: "1000Mi"
            cpu: "1000m"
`)

func TestScanner_createJob(t *testing.T) {
	var scannerJobTemplate batchv1.Job
	err := yaml.Unmarshal(testScannerJobTemplate, &scannerJobTemplate)
	assert.NilError(t, err)

	var expectedScannerJob batchv1.Job
	err = yaml.Unmarshal(expectedScannerJobTemplate, &expectedScannerJob)
	assert.NilError(t, err)

	var expectedScannerJobWithImagePullSecret batchv1.Job
	err = yaml.Unmarshal(expectedScannerJobTemplateWithImagePullSecret, &expectedScannerJobWithImagePullSecret)
	assert.NilError(t, err)

	var expectedScannerJobWithFakeCred batchv1.Job
	err = yaml.Unmarshal(expectedScannerJobTemplateWithFakeCred, &expectedScannerJobWithFakeCred)
	assert.NilError(t, err)

	type fields struct {
		imageToScanData    map[string]*scanData
		progress           types.ScanProgress
		scannerJobTemplate *batchv1.Job
		scanConfig         *_config.ScanConfig
		killSignal         chan bool
		clientset          kubernetes.Interface
		logFields          logrus.Fields
		credentialAdders   []_creds.CredentialAdder
	}
	type args struct {
		data *scanData
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *batchv1.Job
		wantErr bool
	}{
		{
			name:   "failed to create job name",
			fields: fields{},
			args: args{
				data: &scanData{
					imageHash: "image-hash",
					imageID:   "image-id",
					contexts: []*imagePodContext{
						{
							containerName:   "containerName",
							podName:         "podName",
							namespace:       "namespace",
							imagePullSecret: "imagePullSecret",
							imageName:       "notValidImageName",
							podUID:          "podUID",
						},
					},
					scanUUID: "scanUUID",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "sanity without imagePullSecret",
			fields: fields{
				scannerJobTemplate: &scannerJobTemplate,
			},
			args: args{
				data: &scanData{
					imageHash: "image-hash",
					imageID:   "image-id",
					contexts: []*imagePodContext{
						{
							containerName:   "containerName",
							podName:         "podName",
							namespace:       "namespace",
							imagePullSecret: "",
							imageName:       "image-name",
							podUID:          "podUID",
						},
					},
					scanUUID: "scanUUID",
				},
			},
			want:    &expectedScannerJob,
			wantErr: false,
		},
		{
			name: "sanity with imagePullSecret",
			fields: fields{
				scannerJobTemplate: &scannerJobTemplate,
			},
			args: args{
				data: &scanData{
					imageHash: "image-hash",
					imageID:   "image-id",
					contexts: []*imagePodContext{
						{
							containerName:   "containerName",
							podName:         "podName",
							namespace:       "namespace",
							imagePullSecret: "imagePullSecret",

							imageName: "image-name",
							podUID:    "podUID",
						},
					},
					scanUUID: "scanUUID",
				},
			},
			want:    &expectedScannerJobWithImagePullSecret,
			wantErr: false,
		},
		{
			name: "sanity with credentialAdders",
			fields: fields{
				scannerJobTemplate: &scannerJobTemplate,
				credentialAdders: []_creds.CredentialAdder{
					_creds.CreateFakeCredAdder(nil, false),
					_creds.CreateFakeCredAdder(&corev1.EnvVar{
						Name:  "fake-cred-name",
						Value: "fake-cred-value",
					}, true),
				},
			},
			args: args{
				data: &scanData{
					imageHash: "image-hash",
					imageID:   "image-id",
					contexts: []*imagePodContext{
						{
							containerName:   "containerName",
							podName:         "podName",
							namespace:       "namespace",
							imagePullSecret: "",
							imageName:       "image-name",
							podUID:          "podUID",
						},
					},
					scanUUID: "scanUUID",
				},
			},
			want:    &expectedScannerJobWithFakeCred,
			wantErr: false,
		},
		{
			name: "sanity with imagePullSecret and credentialAdders - prioritize imagePullSecret",
			fields: fields{
				scannerJobTemplate: &scannerJobTemplate,
				credentialAdders: []_creds.CredentialAdder{
					_creds.CreateFakeCredAdder(nil, false),
					_creds.CreateFakeCredAdder(&corev1.EnvVar{
						Name:  "fake-cred-name",
						Value: "fake-cred-value",
					}, true),
				},
			},
			args: args{
				data: &scanData{
					imageHash: "image-hash",
					imageID:   "image-id",
					contexts: []*imagePodContext{
						{
							containerName:   "containerName",
							podName:         "podName",
							namespace:       "namespace",
							imagePullSecret: "imagePullSecret",
							imageName:       "image-name",
							podUID:          "podUID",
						},
					},
					scanUUID: "scanUUID",
				},
			},
			want:    &expectedScannerJobWithImagePullSecret,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scanner{
				imageIDToScanData:  tt.fields.imageToScanData,
				progress:           tt.fields.progress,
				scannerJobTemplate: tt.fields.scannerJobTemplate,
				scanConfig:         tt.fields.scanConfig,
				killSignal:         tt.fields.killSignal,
				clientset:          tt.fields.clientset,
				logFields:          tt.fields.logFields,
				credentialAdders:   tt.fields.credentialAdders,
			}
			got, err := s.createJob(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("createJob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				// name is generated with a random uuid
				tt.want.SetName(got.GetName())
			}
			assert.DeepEqual(t, got, tt.want)
		})
	}
}
