package tier

import (
	"encoding/base64"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func md5b64(sum []byte) string { return base64.StdEncoding.EncodeToString(sum) }

// retryOnce keeps the SDKs from retrying for minutes underneath us: the
// transition worker retries on its own schedule.
func retryOnce() policy.RetryOptions {
	return policy.RetryOptions{MaxRetries: 1}
}
