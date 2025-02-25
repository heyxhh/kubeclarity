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

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openclarity/kubeclarity/cli/pkg"
	_export "github.com/openclarity/kubeclarity/cli/pkg/analyzer/export"
	"github.com/openclarity/kubeclarity/cli/pkg/utils"
	sharedanalyzer "github.com/openclarity/kubeclarity/shared/pkg/analyzer"
	"github.com/openclarity/kubeclarity/shared/pkg/analyzer/job"
	"github.com/openclarity/kubeclarity/shared/pkg/converter"
	"github.com/openclarity/kubeclarity/shared/pkg/formatter"
	"github.com/openclarity/kubeclarity/shared/pkg/job_manager"
	sharedutils "github.com/openclarity/kubeclarity/shared/pkg/utils"
)

const inputSBOMName = "input-sbom"

// analyzeCmd represents the analyze command.
var analyzeCmd = &cobra.Command{
	Use:   "analyze [SOURCE]",
	Short: "Content analyzer",
	Long:  `KubeClarity content analyzer.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("an image/directory argument is required")
		}

		return cobra.MaximumNArgs(1)(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		analyzeContent(cmd, args)
	},
}

// nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringP("output", "o", "",
		"set output (default: stdout)")
	analyzeCmd.Flags().StringP("input-type", "i", "",
		fmt.Sprintf("set input type (input type can be %s,%s,%s default:%s)",
			sharedutils.DIR, sharedutils.FILE, sharedutils.IMAGE, sharedutils.IMAGE))
	analyzeCmd.Flags().String("application-id", "",
		"ID of a defined application to associate the exported analysis")
	analyzeCmd.Flags().BoolP("export", "e", false,
		"export analysis results to the backend")
	analyzeCmd.Flags().String("merge-sbom", "",
		"SBOM file to merge to the content analysis results")
}

// nolint:cyclop
func analyzeContent(cmd *cobra.Command, args []string) {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		logger.Fatalf("Unable to get output filename: %v", err)
	}

	inputType, err := cmd.Flags().GetString("input-type")
	if err != nil {
		logger.Fatalf("Unable to get input type: %v", err)
	}

	sourceType, err := sharedutils.ValidateInputType(inputType)
	if err != nil {
		logger.Fatalf("Failed to validate input type: %v", err)
	}

	export, err := cmd.Flags().GetBool("export")
	if err != nil {
		logger.Fatalf("Unable to get export flag: %v", err)
	}

	appID, err := cmd.Flags().GetString("application-id")
	if err != nil {
		logger.Fatalf("Unable to get application ID: %v", err)
	}

	inputSBOMFile, err := cmd.Flags().GetString("merge-sbom")
	if err != nil {
		logger.Fatalf("Unable to get input SBOM filepath: %v", err)
	}

	manager := job_manager.New(appConfig.SharedConfig.Analyzer.AnalyzerList, appConfig.SharedConfig, logger, job.CreateAnalyzerJob)
	results, err := manager.Run(sourceType, args[0])
	if err != nil {
		logger.Fatalf("Failed to run job manager: %v", err)
	}

	hash, err := utils.GenerateHash(sourceType, args[0])
	if err != nil {
		logger.Fatalf("Failed to generate hash for source %s: %v", args[0], err)
	}

	outputFormat := appConfig.SharedConfig.Analyzer.OutputFormat
	if inputSBOMFile != "" {
		cdxBOMBytes, err := convertInputSBOMIfNeeded(inputSBOMFile, outputFormat)
		if err != nil {
			logger.Fatalf("Failed to convert input SBOM file=%s to the results: %v", inputSBOMFile, err)
		}
		results[inputSBOMName] = createResultFromInputSBOM(cdxBOMBytes, inputSBOMFile)
	}

	// Merge results
	mergedResults := sharedanalyzer.NewMergedResults(sourceType, hash)
	for _, result := range results {
		mergedResults = mergedResults.Merge(result.(*sharedanalyzer.Results), outputFormat)
	}

	mergedSboms, err := mergedResults.CreateMergedSBOMBytes(outputFormat, pkg.GitRevision)
	if err != nil {
		logger.Fatalf("Failed to create merged output: %v", err)
	}

	if err := formatter.WriteSBOM(mergedSboms, output); err != nil {
		logger.Fatalf("Failed to write results to file %v: %v ", output, err)
	}

	if export {
		logger.Infof("Exporting analysis results to the backend: %s", appConfig.Backend.Host)
		apiClient := utils.NewHTTPClient(appConfig.Backend)
		// TODO generate application ID
		if err := _export.Export(apiClient, mergedResults, appID); err != nil {
			logger.Errorf("Failed to export analysis results to the backend: %v", err)
		}
	}
}

func createResultFromInputSBOM(sbomBytes []byte, inputSBOMFile string) *sharedanalyzer.Results {
	return sharedanalyzer.CreateResults(sbomBytes, inputSBOMName, inputSBOMFile, sharedutils.SBOM)
}

func convertInputSBOMIfNeeded(inputSBOMFile, outputFormat string) ([]byte, error) {
	inputSBOM, err := os.ReadFile(inputSBOMFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file %s: %v", inputSBOMFile, err)
	}
	inputSBOMFormat := converter.DetermineCycloneDXFormat(inputSBOM)
	if inputSBOMFormat == outputFormat {
		return inputSBOM, nil
	}

	// Create cycloneDX formatter to convert input SBOM to the defined output format.
	cdxFormatter := formatter.New(inputSBOMFormat, inputSBOM)
	if err = cdxFormatter.Decode(inputSBOMFormat); err != nil {
		return nil, fmt.Errorf("failed to decode input SBOM %s: %v", inputSBOMFile, err)
	}
	if err := cdxFormatter.Encode(outputFormat); err != nil {
		return nil, fmt.Errorf("failed to encode input SBOM: %v", err)
	}

	return cdxFormatter.GetSBOMBytes(), nil
}
