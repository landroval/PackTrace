package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/cli"
)

func TestAdvisoryCandidatesPolicyStrictOptionalBool(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		valid, want bool
	}{
		{"omitted", "", true, false},
		{"false", `"advisoryCandidates":false,`, true, false},
		{"true", `"advisoryCandidates":true,`, true, true},
		{"null", `"advisoryCandidates":null,`, false, false},
		{"string", `"advisoryCandidates":"true",`, false, false},
		{"number", `"advisoryCandidates":1,`, false, false},
		{"array", `"advisoryCandidates":[],`, false, false},
		{"object", `"advisoryCandidates":{},`, false, false},
		{"duplicate", `"advisoryCandidates":false,"advisoryCandidates":true,`, false, false},
		{"unknown", `"advisoryCandidate":true,`, false, false},
		{"case-variant", `"AdvisoryCandidates":true,`, false, false},
		{"case-null", `"ADVISORYCANDIDATES":null,`, false, false},
		{"case-duplicate", `"advisoryCandidates":true,"AdvisoryCandidates":false,`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(strings.Replace(policyJSON, "{", "{"+tc.field, 1)))
			if (err == nil) != tc.valid || err == nil && p.AdvisoryCandidates != tc.want {
				t.Fatalf("candidate policy: %+v %v", p, err)
			}
			if err == nil {
				data, err := json.Marshal(p)
				if err != nil || strings.Contains(string(data), `"advisoryCandidates"`) != tc.want {
					t.Fatalf("optional field serialization: %s %v", data, err)
				}
			}
		})
	}
}

func TestAdvisoryCandidatesPolicyManagerBound(t *testing.T) {
	for _, manager := range []string{"npm@8.19.4", "npm@10.9.4", "npm@11.6.2", "bun@1.3.2", "bun@1.4.2", "npm@99.0.0", "npm", "auto"} {
		t.Run(manager, func(t *testing.T) {
			p, err := ParsePolicy([]byte(policyJSON))
			if err != nil {
				t.Fatal(err)
			}
			p.Manager = manager
			p.AdvisoryCandidates = true
			want := oneOf(manager, "npm@8.19.4", "npm@10.9.4", "npm@11.6.2")
			if err := ValidatePolicy(p); (err == nil) != want {
				t.Fatalf("manager accepted=%v want=%v: %v", err == nil, want, err)
			}
			if strings.HasPrefix(manager, "bun@") {
				p.AdvisoryCandidates = false
				if err := ValidatePolicy(p); err != nil {
					t.Fatal("opt-out changed supported Bun policy", err)
				}
			}
		})
	}
}

func TestAdvisoryCandidatesPolicyIndependentPinAndDefaults(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	r := cli.ScanArgumentRequest{PolicyPath: "external/policy.json", Checks: cli.ArgumentCheckIntegrity, Output: "-", Manager: "auto"}
	if plan, err := Configure(r, p); err != nil || plan.Policy.AdvisoryCandidates || plan.TrustedPolicyDigest != "" || plan.Privacy != "portable" {
		t.Fatalf("legacy default changed: %+v %v", plan, err)
	}
	p.AdvisoryCandidates = true
	for _, pin := range []string{"", "sha1-weak", "sha256-invalid", "not-a-pin"} {
		r.TrustedPolicyDigest = pin
		if _, err := Configure(r, p); err != ErrOptions {
			t.Fatalf("candidate permission without supported independent pin %q: %v", pin, err)
		}
	}
	// A snapshot pin, reason and provenance do not substitute for a policy pin.
	r.TrustedPolicyDigest = ""
	r.TrustedSnapshotDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := Configure(r, p); err != ErrOptions {
		t.Fatalf("snapshot pin substituted for policy authority: %v", err)
	}
	r.TrustedSnapshotDigest = ""
	r.TrustedPolicyDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, privacy := range []string{"", "portable", "local"} {
		r.Privacy = privacy
		plan, err := Configure(r, p)
		if err != nil || !plan.Policy.AdvisoryCandidates || plan.TrustedPolicyDigest != r.TrustedPolicyDigest || plan.Policy.NPMRegistry != "" || len(plan.Policy.NPMOrigins) != 0 || plan.Policy.MinimumAssurance != p.MinimumAssurance {
			t.Fatalf("candidate grant changed other authority: %+v %v", plan, err)
		}
	}
}

func TestAdvisoryCandidatesPolicyCannotWeakenChecksOrPrivacy(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	p.AdvisoryCandidates = true
	p.RequirePortable = true
	p.FailOn = []string{"integrity"}
	r := cli.ScanArgumentRequest{PolicyPath: "external/policy.json", Checks: cli.ArgumentCheckIntegrity, Output: "-", Manager: "auto", TrustedPolicyDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for _, privacy := range []string{"", "portable"} {
		r.Privacy = privacy
		plan, err := Configure(r, p)
		if err != nil || plan.Privacy != "portable" || plan.FailOn != cli.ArgumentCheckIntegrity {
			t.Fatalf("portable/fail-on requirement changed: %+v %v", plan, err)
		}
	}
	for _, mutate := range []func(*cli.ScanArgumentRequest){
		func(r *cli.ScanArgumentRequest) { r.Privacy = "local" },
		func(r *cli.ScanArgumentRequest) { r.Checks = cli.ArgumentCheckMalicious },
		func(r *cli.ScanArgumentRequest) { r.FailOn = cli.ArgumentCheckMalicious },
		func(r *cli.ScanArgumentRequest) { r.Manager = "bun@1.4.2" },
	} {
		request := r
		mutate(&request)
		if _, err := Configure(request, p); err != ErrOptions {
			t.Fatalf("candidate permission weakened parent options: %+v %v", request, err)
		}
	}
	p.FailOn = []string{"malicious"}
	if err := ValidatePolicy(p); err != ErrPolicy {
		t.Fatalf("candidate permission weakened policy fail-on subset: %v", err)
	}
}
