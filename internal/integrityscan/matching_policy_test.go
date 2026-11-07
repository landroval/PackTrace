package integrityscan

import (
	"packtrace/internal/cli"
	"packtrace/internal/inventory"
	"strings"
	"testing"
)

func matchingPlan(t *testing.T) Plan {
	t.Helper()
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	p.RequiredChecks = []string{"malicious"}
	p.References = []Reference{}
	p.NPMOrigins = []NPMOriginRule{{Location: "node_modules/left-pad", Name: "left-pad", Version: "1.0.0", Origin: npmTarballOrigin("left-pad", "1.0.0")}}
	r := cli.ScanArgumentRequest{PolicyPath: "policy.json", Checks: cli.ArgumentCheckMalicious, Privacy: "portable", Output: "-", Manager: "auto", TrustedPolicyDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	plan, err := Configure(r, p)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func TestNPMOriginsPolicyClosedExactPinned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Policy)
	}{
		{"bun", func(p *Policy) { p.Manager = "bun@1.4.2" }},
		{"duplicate", func(p *Policy) { p.NPMOrigins = append(p.NPMOrigins, p.NPMOrigins[0]) }},
		{"case-location", func(p *Policy) {
			r := p.NPMOrigins[0]
			r.Location = strings.ToUpper(r.Location)
			p.NPMOrigins = append(p.NPMOrigins, r)
		}},
		{"escape", func(p *Policy) { p.NPMOrigins[0].Location = "../node_modules/left-pad" }},
		{"alias", func(p *Policy) { p.NPMOrigins[0].Name = "npm:left-pad" }},
		{"uppercase", func(p *Policy) { p.NPMOrigins[0].Name = "Left-pad" }},
		{"range", func(p *Policy) { p.NPMOrigins[0].Version = "^1.0.0" }},
		{"loose", func(p *Policy) { p.NPMOrigins[0].Version = "v1.0.0" }},
		{"mirror", func(p *Policy) { p.NPMOrigins[0].Origin = "https://example.invalid/left-pad/-/left-pad-1.0.0.tgz" }},
		{"query", func(p *Policy) { p.NPMOrigins[0].Origin += "?x" }},
		{"port", func(p *Policy) {
			p.NPMOrigins[0].Origin = strings.Replace(p.NPMOrigins[0].Origin, ".org/", ".org:443/", 1)
		}},
		{"cap", func(p *Policy) { p.NPMOrigins = make([]NPMOriginRule, 65) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := matchingPlan(t).Policy
			tc.change(&p)
			if ValidatePolicy(p) == nil {
				t.Fatal("accepted")
			}
		})
	}
	plan := matchingPlan(t)
	request := cli.ScanArgumentRequest{PolicyPath: "policy.json", Checks: cli.ArgumentCheckMalicious, Privacy: "portable", Output: "-", Manager: "auto"}
	if _, err := Configure(request, plan.Policy); err == nil {
		t.Fatal("unpinned correspondence")
	}
	p := plan.Policy
	p.NPMOrigins = nil
	if _, err := Configure(request, p); err != nil {
		t.Fatal("legacy default changed", err)
	}
	p = plan.Policy
	p.NPMOrigins = []NPMOriginRule{{Location: "node_modules/@scope/pkg", Name: "@scope/pkg", Version: "1.2.3-rc.1+build", Origin: npmTarballOrigin("@scope/pkg", "1.2.3-rc.1+build")}}
	if ValidatePolicy(p) != nil {
		t.Fatal("canonical scoped rule rejected")
	}
}
func TestMatchingRuleDoesNotPromoteUnknownAliasOrOtherEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Plan, *matchingFixture)
	}{
		{"unpin", func(p *Plan, f *matchingFixture) { p.TrustedPolicyDigest = "" }},
		{"other-version", func(p *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Version = "2.0.0" }},
		{"other-origin", func(p *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Origin = "https://private.invalid/pkg.tgz"
		}},
		{"other-location", func(p *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Location = "node_modules/other" }},
		{"bun", func(p *Plan, f *matchingFixture) { f.inv.Selection.Family = "bun" }},
		{"incomplete", func(p *Plan, f *matchingFixture) { f.inv.Model.Evidence[0].Complete = false }},
		{"not-selected", func(p *Plan, f *matchingFixture) { f.inv.Selection.File = "npm-shrinkwrap.json" }},
		{"invalid-version", func(p *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Fields["version-state"] = "invalid" }},
		{"unknown-name", func(p *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Fields["name-qualification"] = "alias-declaration"
		}},
		{"link", func(p *Plan, f *matchingFixture) { f.inv.Model.Observations[0].Fields["link"] = "true" }},
		{"alias", func(p *Plan, f *matchingFixture) {
			f.inv.Model.Observations[0].Requirements = []inventory.DependencyGroup{{State: inventory.FieldValue, Entries: []inventory.DeclaredDependency{{Name: "left-pad", Requirement: "npm:left-pad@1.0.0", State: inventory.FieldValue}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := matchingPlan(t)
			f := newMatchingFixture()
			tc.change(&p, &f)
			if matchingRule(p, f.inv, f.inv.Model.Observations[0]) != 0 {
				t.Fatal("promoted")
			}
		})
	}
	p := matchingPlan(t)
	f := newMatchingFixture()
	if matchingRule(p, f.inv, f.inv.Model.Observations[0]) != 1 {
		t.Fatal("exact tuple rejected")
	}
}
