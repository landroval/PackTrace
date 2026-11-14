package integrityscan

import (
	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
	"testing"
)

func TestPNPMPolicyAndIntegrityAuthorityBoundaries(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	p.Manager = "pnpm@lockfile-9"
	if ValidatePolicy(p) != nil {
		t.Fatal("format policy rejected")
	}
	for _, change := range []func(*Policy){
		func(p *Policy) { p.AdvisoryCandidates = true },
		func(p *Policy) { p.NPMRegistry = "https://registry.npmjs.org" },
		func(p *Policy) { p.BunCacheDirectory = "/owned-inert" },
	} {
		forged := p
		change(&forged)
		if ValidatePolicy(forged) == nil {
			t.Fatal("pnpm policy gained source authority")
		}
	}
	plan := Plan{Manager: p.Manager, Policy: p, Checks: 4}
	record := badRecord(0, integrity.BindingClaim{}, integrity.GapBinding)
	if ValidateRecord(plan, record, "policy") != nil {
		t.Fatal("incomplete record refused")
	}
	if _, gaps := integrity.ResolveReferenceBinding(Binding(plan, 0, integrity.BindingClaim{PackageID: "forged"}, "policy")); len(gaps) == 0 {
		t.Fatal("pnpm format gained a reference binding")
	}
	for _, change := range []func(*Record){
		func(r *Record) { r.Lock.PackageID = "forged" },
		func(r *Record) { r.ObservedEntries = 1 },
		func(r *Record) { r.Assessment.SuppliedComparisonComplete = true },
		func(r *Record) { r.Assessment.Assurance = integrity.AssuranceLockfile },
	} {
		forged := record
		change(&forged)
		if ValidateRecord(plan, forged, "policy") == nil {
			t.Fatal("pnpm record gained integrity authority")
		}
	}
	inv := projectinventory.Result{Selection: projectinventory.Selection{Family: "pnpm"}}
	if len(lockedFromInventory(inv).claims) != 0 || candidateLookupPermission(plan) {
		t.Fatal("pnpm gained binding or lookup permission")
	}
	for _, file := range []string{"bun.lock", "package-lock.json", "npm-shrinkwrap.json"} {
		if profileLockPair(p.Manager, file) {
			t.Fatal("mismatched profile/file", file)
		}
	}
	if !profileLockPair(p.Manager, "pnpm-lock.yaml") || profileLockPair("npm@10.9.4", "pnpm-lock.yaml") || profileLockPair("bun@1.3.x", "pnpm-lock.yaml") {
		t.Fatal("explicit format gate")
	}
}
