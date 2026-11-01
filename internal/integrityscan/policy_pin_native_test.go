package integrityscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
)

func TestOwnedPolicyPinAuthenticatesActualBytesAndIndependentComparison(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned native Linux unit; not release qualification")
	}
	root, name, p := ownedFixture(t)
	p.MinimumAssurance = "independently-anchored"
	plan, hash := fixturePlan(t, name, p)
	obs, e := AcquirePolicyPinned(context.Background(), name, root, hash)
	if e != nil || obs.MatchedOperatorDigest != hash {
		t.Fatal("operator pin not verified against actual source", e)
	}
	if _, e = AcquirePolicyPinned(context.Background(), name, root, "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); e == nil {
		t.Fatal("wrong pin accepted")
	}
	request := cli.ScanArgumentRequest{PolicyPath: name, TrustedPolicyDigest: hash, Checks: cli.ArgumentCheckIntegrity, Manager: "auto", Privacy: "portable", Output: "-"}
	plan, e = Configure(request, p)
	if e != nil {
		t.Fatal("pinned independent mode refused", e)
	}
	var records []Record
	summary, e := Acquire(context.Background(), root, filepath.Dir(name), hash, plan, func(r Record) error { records = append(records, r); return nil })
	if e != nil || len(records) != 1 || records[0].Assessment.Assurance != integrity.AssuranceIndependent || len(records[0].Assessment.Differences) == 0 {
		t.Fatalf("independent comparison missing: records=%+v error=%v", records, e)
	}
	if summary.Qualified || !summary.AuthorityComplete {
		t.Fatal("operator reference authority missing or promoted to global qualification")
	}
	if e = ValidateRecord(plan, records[0], hash); e != nil {
		t.Fatal("parent rejected genuine pinned binding", e)
	}
	unpinned := plan
	unpinned.TrustedPolicyDigest = ""
	if ValidateRecord(unpinned, records[0], hash) == nil {
		t.Fatal("worker promoted unpinned parent authority")
	}
	// A caller cannot combine a new continuity hash with the old operator pin.
	data, e := os.ReadFile(name)
	if e != nil {
		t.Fatal("owned policy")
	}
	changed := append(data, ' ')
	if os.WriteFile(name, changed, 0600) != nil {
		t.Fatal("owned policy mutation")
	}
	if _, e = AcquirePolicyPinned(context.Background(), name, root, hash); e == nil {
		t.Fatal("mutated policy accepted")
	}
	emitted := false
	if _, e = Acquire(context.Background(), root, filepath.Dir(name), sourceSRI(changed), plan, func(Record) error { emitted = true; return nil }); e == nil || emitted {
		t.Fatal("continuity substituted for pinned authority")
	}
}

func TestOperatorPinIsNotAcceptedFromPolicyText(t *testing.T) {
	var p map[string]any
	if json.Unmarshal([]byte(policyJSON), &p) != nil {
		t.Fatal("fixture")
	}
	p["trustedPolicyDigest"] = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	raw, _ := json.Marshal(p)
	if _, e := ParsePolicy(raw); e == nil {
		t.Fatal("policy granted its own operator trust")
	}
}
