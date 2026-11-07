package execution

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"packtrace/internal/integrityscan"
)

// This is continuity of compiled defaults, not a file source or trust pin.
func builtinPolicyHash(plan integrityscan.Plan) string {
	data, e := json.Marshal(plan.Policy)
	if e != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
