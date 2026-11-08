package integrityscan

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestBunCacheIsExplicitPinnedInputNotOriginGrant(t *testing.T) {
	plan := matchingPlan(t)
	plan.Manager = "bun@1.3.x"
	plan.Policy.Manager = plan.Manager
	plan.Policy.NPMOrigins = nil
	plan.Policy.BunCacheDirectory = filepath.Join(t.TempDir(), "cache")
	if ValidatePlanPolicy(plan) != nil {
		t.Fatal("valid pinned additional input refused")
	}
	plan.TrustedPolicyDigest = ""
	if ValidatePlanPolicy(plan) == nil {
		t.Fatal("unpinned additional input admitted")
	}
	plan = matchingPlan(t)
	plan.Policy.BunCacheDirectory = filepath.Join(t.TempDir(), "cache")
	if ValidatePolicy(plan.Policy) == nil {
		t.Fatal("npm policy activated Bun cache purpose")
	}
	plan.Policy.Manager = "bun@1.3.x"
	plan.Policy.NPMOrigins = nil
	plan.Policy.BunCacheDirectory = "relative/cache"
	if ValidatePolicy(plan.Policy) == nil {
		t.Fatal("relative cache accepted")
	}
	plan.Policy.BunCacheDirectory = filepath.Join(t.TempDir(), "cache")
	data, err := json.Marshal(plan.Policy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		t.Fatal("policy fixture")
	}
	fields["BunCacheDirectory"] = fields["bunCacheDirectory"]
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePolicy(data); err == nil {
		t.Fatal("case alias accepted")
	}
}
