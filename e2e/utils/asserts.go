package utils

import (
	"testing"

	"gotest.tools/assert"

	"github.com/openclarity/kubeclarity/api/client/client"
	"github.com/openclarity/kubeclarity/api/client/client/operations"
	"github.com/openclarity/kubeclarity/api/client/models"
)

func AssertGetRuntimeScanResults(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs, want *models.RuntimeScanResults) {
	params := operations.NewGetRuntimeScanResultsParams()
	res, err := kubeclarityAPI.Operations.GetRuntimeScanResults(params)
	assert.NilError(t, err)
	assert.DeepEqual(t, res.Payload, want)
}
