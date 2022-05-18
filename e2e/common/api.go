package common


import (
	"github.com/openclarity/kubeclarity/api/client/models"
	"testing"

	"gotest.tools/assert"

	"github.com/openclarity/kubeclarity/api/client/client"
	"github.com/openclarity/kubeclarity/api/client/client/operations"
)

func GetRuntimeScanResults(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs) *models.RuntimeScanResults {
	params := operations.NewGetRuntimeScanResultsParams()
	res, err := kubeclarityAPI.Operations.GetRuntimeScanResults(params)
	assert.NilError(t, err)

	return res.Payload
}

func GetPackages(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs) *operations.GetPackagesOKBody {
	params := operations.NewGetPackagesParams()
	res, err := kubeclarityAPI.Operations.GetPackages(params)
	assert.NilError(t, err)

	return res.Payload
}

func GetApplicationResources(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs) *operations.GetApplicationResourcesOKBody {
	params := operations.NewGetApplicationResourcesParams()
	res, err := kubeclarityAPI.Operations.GetApplicationResources(params)
	assert.NilError(t, err)

	return res.Payload
}

func GetVulnerabilities(t *testing.T, kubeclarityAPI *client.KubeClarityAPIs) *operations.GetVulnerabilitiesOKBody {
	params := operations.NewGetVulnerabilitiesParams()
	res, err := kubeclarityAPI.Operations.GetVulnerabilities(params)
	assert.NilError(t, err)

	return res.Payload
}

