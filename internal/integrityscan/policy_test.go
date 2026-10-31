package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/cli"
)

const policyJSON = `{"version":1,"designation":"user-designated","reason":"reviewed owned baseline","provenance":"fixture preparation receipt","manager":"npm@10.9.4","requiredChecks":["integrity"],"failOn":[],"requireHardMemoryLimit":false,"minimumAssurance":"lockfile-consistent","references":[{"location":"node_modules/pkg","lockKey":"node_modules/pkg","name":"pkg","version":"1.0.0","origin":"fixture:private","classification":"private","expectedSRI":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","archive":"pkg.tgz","context":"none"}]}`

func TestPolicyRejectsMissingAuthorityAndAmbiguousMappings(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["designation"] = "" },
		func(p map[string]any) { p["reason"] = "" },
		func(p map[string]any) { p["provenance"] = "" },
		func(p map[string]any) { p["network"] = true },
		func(p map[string]any) { p["requiredChecks"] = []any{"integrity", "integrity"} },
		func(p map[string]any) { p["requireHardMemoryLimit"] = true },
		func(p map[string]any) { p["references"] = append(p["references"].([]any), p["references"].([]any)[0]) },
		func(p map[string]any) { p["references"].([]any)[0].(map[string]any)["location"] = "../escape" },
		func(p map[string]any) { p["references"].([]any)[0].(map[string]any)["archive"] = "../escape.tgz" },
		func(p map[string]any) { p["references"].([]any)[0].(map[string]any)["expectedSRI"] = "sha1-weak" },
	} {
		var p map[string]any
		if json.Unmarshal([]byte(policyJSON), &p) != nil {
			t.Fatal("fixture")
		}
		mutate(p)
		data, _ := json.Marshal(p)
		if _, err := ParsePolicy(data); err == nil || strings.Contains(err.Error(), "escape") {
			t.Fatalf("accepted malformed/unsafe policy: %s %v", data, err)
		}
	}
	if _, err := ParsePolicy([]byte(strings.Replace(policyJSON, `"version":1`, `"version":1,"version":1`, 1))); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestPolicyEffectiveSettingsAreParentOwned(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	request := cli.ScanArgumentRequest{Path: "fixture", PolicyPath: "external/policy.json", Checks: cli.ArgumentCheckIntegrity, Format: "json", Privacy: "portable", Manager: "auto", Output: "-"}
	plan, err := Configure(request, p)
	if err != nil || plan.Manager != "npm@10.9.4" || plan.Checks != cli.ArgumentCheckIntegrity {
		t.Fatalf("effective settings: %+v %v", plan, err)
	}
	independent := p
	independent.MinimumAssurance = "independently-anchored"
	if _, err := Configure(request, independent); err == nil {
		t.Fatal("independent policy must refuse before target access without exclusion capability")
	}
	for _, mutate := range []func(*cli.ScanArgumentRequest){
		func(r *cli.ScanArgumentRequest) { r.Checks = cli.ArgumentCheckMalicious },
		func(r *cli.ScanArgumentRequest) { r.Privacy = "local" },
		func(r *cli.ScanArgumentRequest) { r.Output = "inside/report.json" },
		func(r *cli.ScanArgumentRequest) { r.StateDir = "unqualified-store" },
		func(r *cli.ScanArgumentRequest) { r.Manager = "bun@1.4.2" },
	} {
		r := request
		mutate(&r)
		if _, err := Configure(r, p); err == nil {
			t.Fatalf("unsupported/weakening request accepted %+v", r)
		}
	}
}
