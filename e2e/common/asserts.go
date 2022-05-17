package common

import (
	"testing"

	"gotest.tools/assert"

	"github.com/openclarity/kubeclarity/api/client/client"
	"github.com/openclarity/kubeclarity/api/client/client/operations"
)

func AssertGetRuntimeScanResults(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs) {
	params := operations.NewGetRuntimeScanResultsParams()
	res, err := kubeclarityAPI.Operations.GetRuntimeScanResults(params)
	assert.NilError(t, err)

	assert.Assert(t, res.Payload.Counters.Resources > 0)
	assert.Assert(t, res.Payload.Counters.Vulnerabilities > 0)
	assert.Assert(t, res.Payload.Counters.Packages > 0)
	assert.Assert(t, res.Payload.Counters.Applications > 0)

	assert.Assert(t, len(res.Payload.VulnerabilityPerSeverity) > 0)
}
