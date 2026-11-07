package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/projectinventory"
)

func engineMaterial() PolicyMaterial {
	p := ProjectEvidence{Scope: 1, Manifest: 2, Lock: 1, ManifestSHA256: strings.Repeat("1", 64), LockSHA256: strings.Repeat("2", 64), Profile: "npm@10.9.4", LockFile: "package-lock.json"}
	return PolicyMaterial{Project: p, Scope: FindingScope{Project: ProjectFingerprint(p), Category: "malicious", Rule: "osv-npm", Class: "locked", Package: "left-pad", Version: "1.0.0", Origin: npmTarballOrigin("left-pad", "1.0.0"), Instance: "node_modules/left-pad", Advisory: "MAL-2026-1"}, Observation: 1, Advisory: 1, SourceSHA256: p.LockSHA256, LockSourceSHA256: p.LockSHA256, OriginalSHA256: strings.Repeat("3", 64), Profile: "openssf-malicious-v1"}
}
func engineException(m PolicyMaterial) Exception {
	return Exception{ID: "PRIVATE-id", Reason: "PRIVATE-reason", Owner: "PRIVATE-owner", ApprovedAt: "2026-10-01T00:00:00Z", ExpiresAt: "2026-10-31T00:00:00Z", Scope: m.Scope, Acceptance: AcceptanceFingerprint(m)}
}
func engineFixture(t *testing.T) (Plan, projectinventory.PublicInventory, []AdvisoryDecision, PolicyMaterial) {
	t.Helper()
	m := engineMaterial()
	fixture := newMatchingFixture().inv
	fixture.Model.Evidence = append(fixture.Model.Evidence, projectinventory.Evidence{ID: 2, Scope: 1, Location: "package.json", Method: "native-input-lease", Complete: true})
	inv := projectinventory.PortableMatching(fixture)
	p := Policy{Version: 1, Designation: "user-designated", Reason: "reviewed", Provenance: "assertion", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious"}, FailOn: []string{"malicious"}, MinimumAssurance: "lockfile-consistent", References: []Reference{}, NPMOrigins: []NPMOriginRule{{Location: m.Scope.Instance, Name: m.Scope.Package, Version: m.Scope.Version, Origin: m.Scope.Origin}}, Exceptions: []Exception{engineException(m)}}
	pin := "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	plan, e := Configure(cli.ScanArgumentRequest{PolicyPath: "policy.json", Manager: "auto", Checks: cli.ArgumentCheckMalicious, Privacy: "portable", Output: "-", TrustedPolicyDigest: pin}, p)
	if e != nil {
		t.Fatal(e)
	}
	d := AdvisoryDecision{Sequence: 0, Observation: 1, Advisory: 1, Affected: 0, Rule: 1, VersionOutcome: "match", Outcome: "match", FullyEvaluated: true, Category: "malicious", Profile: m.Profile, Activity: "not-withdrawn", Origin: "operator-npm-rule", Source: "qualified", EnforcementEligible: true, Support: []AdvisorySupport{{Version: 0, Range: -1}}, Gaps: []string{}}
	return plan, inv, []AdvisoryDecision{d}, m
}
func TestEngineStrictExceptionPolicy(t *testing.T) {
	p, _ := ParsePolicy([]byte(policyJSON))
	p.Exceptions = []Exception{engineException(engineMaterial())}
	raw, _ := json.Marshal(p)
	if _, e := ParsePolicy(raw); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Exceptions = append(p.Exceptions, p.Exceptions[0]) },
		func(p *Policy) { p.Exceptions[0].ExpiresAt = "2026-11-01T00:00:00Z" },
		func(p *Policy) { p.Exceptions[0].ApprovedAt = "2026-10-01T00:00:00+00:00" },
		func(p *Policy) { p.Exceptions[0].ExpiresAt = p.Exceptions[0].ApprovedAt },
		func(p *Policy) { p.Exceptions[0].Scope.Instance = "*" },
		func(p *Policy) { p.Exceptions[0].Scope.Project = "" },
		func(p *Policy) { p.MaxExceptionDays = 366 },
		func(p *Policy) { p.MaxExceptionDays = -1 },
	} {
		q := p
		q.Exceptions = append([]Exception{}, p.Exceptions...)
		mutate(&q)
		b, _ := json.Marshal(q)
		if _, e := ParsePolicy(b); e == nil {
			t.Fatal("invalid exception admitted", string(b))
		}
	}
	for _, pair := range [][2]string{{`"id":`, `"ID":`}, {`"scope":`, `"scope":null,"other":`}, {`"exceptions":`, `"Exceptions":`}, {`"acceptance":`, `"Acceptance":`}, {`"project":`, `"Project":`}} {
		b := strings.Replace(string(raw), pair[0], pair[1], 1)
		if _, e := ParsePolicy([]byte(b)); e == nil {
			t.Fatal("case/null grant admitted")
		}
	}
	p.MaxExceptionDays = 31
	p.Exceptions[0].ExpiresAt = "2026-11-01T00:00:00Z"
	if ValidatePolicy(p) != nil {
		t.Fatal("bounded override rejected")
	}
}
func TestEngineUTCPrecisionAndBounds(t *testing.T) {
	for _, value := range []string{"2026-10-01T00:00:00Z", "2026-10-01T00:00:00.000Z", "2026-10-01T00:00:00.123456789Z"} {
		if _, e := utcTime(value); e != nil {
			t.Fatal("RFC3339 UTC refused", value)
		}
	}
	for _, value := range []string{"2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00,1Z", "2026-10-01T00:00:00.1234567891Z", "2026-10-01T00:00:00.Z"} {
		if _, e := utcTime(value); e == nil {
			t.Fatal("invalid UTC admitted", value)
		}
	}
	p, _ := ParsePolicy([]byte(policyJSON))
	p.Exceptions = make([]Exception, 65)
	for i := range p.Exceptions {
		p.Exceptions[i] = engineException(engineMaterial())
	}
	if ValidatePolicy(p) == nil {
		t.Fatal("exception count unbounded")
	}
	for _, raw := range []string{strings.Replace(policyJSON, `"version":1`, `"maxExceptionDays":0,"version":1`, 1), strings.Replace(policyJSON, `"version":1`, `"exceptions":null,"version":1`, 1)} {
		if _, e := ParsePolicy([]byte(raw)); e == nil {
			t.Fatal("explicit invalid optional schema admitted")
		}
	}
}

func TestEngineDefaultsPrecedenceAndPin(t *testing.T) {
	r := cli.ScanArgumentRequest{Manager: "auto", Checks: cli.ArgumentCheckIntegrity, Privacy: "portable", Output: "report.json"}
	p, e := ConfigureBuiltin(r)
	if e != nil || ValidatePlanPolicy(p) != nil || p.Policy.Designation != "built-in" || p.PolicyFile != "" {
		t.Fatal(p, e)
	}
	p.Policy.AdvisoryCandidates = true
	if ValidatePlanPolicy(p) == nil {
		t.Fatal("built-in granted authority")
	}
	r.TrustedPolicyDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, e := ConfigureBuiltin(r); e == nil {
		t.Fatal("pin without source")
	}
	explicit, _ := ParsePolicy([]byte(policyJSON))
	explicit.FailOn = []string{"integrity"}
	r.PolicyPath = "policy.json"
	r.TrustedPolicyDigest = ""
	r.Provided = cli.ArgumentOptionFailOn
	if _, e := Configure(r, explicit); e == nil {
		t.Fatal("explicit none silently repaired")
	}
	r.Provided = 0
	if p, e := Configure(r, explicit); e != nil || p.FailOn != cli.ArgumentCheckIntegrity {
		t.Fatal("omission did not inherit")
	}
	explicit.Exceptions = []Exception{engineException(engineMaterial())}
	if _, e := Configure(r, explicit); e == nil {
		t.Fatal("exceptions without independent pin")
	}
	explicit.Exceptions = nil
	explicit.MaxExceptionDays = 30
	if _, e := Configure(r, explicit); e == nil {
		t.Fatal("lifetime configuration without pin")
	}
}
func TestEngineEvaluationTimePrivacyAndEvidence(t *testing.T) {
	p, inv, ds, m := engineFixture(t)
	for _, tc := range []struct {
		when        string
		accepted    bool
		disposition string
	}{{"2026-09-30T23:59:59Z", false, "future"}, {"2026-10-01T00:00:00Z", true, "applied"}, {"2026-10-30T23:59:59Z", true, "applied"}, {"2026-10-31T00:00:00Z", false, "expired"}} {
		now, _ := time.Parse(time.RFC3339, tc.when)
		v, e := EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m}, false, now)
		if e != nil || len(v.Findings) != 1 || v.Findings[0].Accepted != tc.accepted || v.Exceptions[0].Disposition != tc.disposition {
			t.Fatal(v, e)
		}
		if v.Findings[0].Enforced == tc.accepted {
			t.Fatal("enforcement not independent")
		}
		b, _ := json.Marshal(v)
		for _, s := range []string{"PRIVATE", "left-pad", m.OriginalSHA256, m.Scope.Project, "sha256-"} {
			if strings.Contains(string(b), s) {
				t.Fatal("portable leak", s)
			}
		}
		if ValidatePolicyEvaluation(p, nil, inv, ds, []PolicyMaterial{m}, false, now, v) != nil {
			t.Fatal("re-evaluation")
		}
		v.Findings[0].Accepted = !v.Findings[0].Accepted
		if ValidatePolicyEvaluation(p, nil, inv, ds, []PolicyMaterial{m}, false, now, v) == nil {
			t.Fatal("forged acceptance")
		}
	}
	for _, limited := range []bool{false, true} {
		v, e := EvaluatePolicy(p, nil, inv, ds, nil, limited, matchingNow)
		if e != nil || v.Findings[0].Accepted || v.EnforcedUnaccepted != 1 {
			t.Fatal("missing evidence accepted", v, e)
		}
	}
	changed := m
	changed.OriginalSHA256 = strings.Repeat("4", 64)
	v, e := EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{changed}, false, matchingNow)
	if e != nil || v.Findings[0].Accepted {
		t.Fatal("changed original accepted", e)
	}
	p.Privacy = "local"
	v, e = EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m}, false, matchingNow)
	if e != nil || v.Findings[0].Acceptance != AcceptanceFingerprint(m) || v.Findings[0].Tracking == "" {
		t.Fatal("local material missing", e)
	}
	ds[0].Candidate = true
	if _, e := EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m}, false, matchingNow); e == nil {
		t.Fatal("candidate accepted")
	}
}
func TestEngineExceptionExactScopeAndPinContinuity(t *testing.T) {
	p, inv, ds, m := engineFixture(t)
	for _, mutate := range []func(*FindingScope){func(s *FindingScope) { s.Version = "2.0.0" }, func(s *FindingScope) { s.Instance = "node_modules/other" }, func(s *FindingScope) { s.Origin = npmTarballOrigin("other", "1.0.0") }, func(s *FindingScope) { s.Advisory = "MAL-2026-2" }, func(s *FindingScope) { s.Project = sourceSRI([]byte("other project")) }, func(s *FindingScope) { s.Category = "vulnerability" }} {
		q := p
		q.Policy.Exceptions = append([]Exception{}, p.Policy.Exceptions...)
		mutate(&q.Policy.Exceptions[0].Scope)
		v, e := EvaluatePolicy(q, nil, inv, ds, []PolicyMaterial{m}, false, matchingNow)
		if e != nil || v.Findings[0].Accepted {
			t.Fatal("exact scope did not bind", e)
		}
	}
	p.TrustedPolicyDigest = sourceSRI([]byte("different independently verified policy bytes"))
	p.Policy.Exceptions[0].ID = "changed ID"
	p.Policy.Exceptions[0].Reason = "changed reason"
	p.Policy.Exceptions[0].Owner = "changed owner"
	v, e := EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m}, false, matchingNow)
	if e != nil || !v.Findings[0].Accepted {
		t.Fatal("policy exception text or pin made acceptance circular", e)
	}
	// Container ordinals and snapshot IDs are absent from the fingerprint input;
	// refreshing a snapshot cannot renew the fixed approval/expiry interval.
	v, e = EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m}, false, matchingNow.AddDate(0, 1, 0))
	if e != nil || v.Findings[0].Accepted || v.Exceptions[0].Disposition != "expired" {
		t.Fatal("acceptance clock renewed", e)
	}
	ds[0].Candidate = true
	v, e = EvaluatePolicy(p, nil, inv, ds, nil, false, matchingNow)
	if e != nil || len(v.Findings) != 0 || v.EnforcedUnaccepted != 0 {
		t.Fatal("candidate promoted", e)
	}
}

func TestEngineFingerprintsAndMalformedMaterials(t *testing.T) {
	p, inv, ds, m := engineFixture(t)
	initial := AcceptanceFingerprint(m)
	renumber := m
	renumber.Project.Manifest = 10
	renumber.Project.Lock = 11
	renumber.Observation = 9
	renumber.Advisory = 5
	if AcceptanceFingerprint(renumber) != initial {
		t.Fatal("container IDs in stable fingerprint")
	}
	for _, mutate := range []func(*PolicyMaterial){func(m *PolicyMaterial) { m.OriginalSHA256 = strings.Repeat("5", 64) }, func(m *PolicyMaterial) {
		m.Project.LockSHA256 = strings.Repeat("5", 64)
		m.LockSourceSHA256 = m.Project.LockSHA256
		m.SourceSHA256 = m.Project.LockSHA256
		m.Scope.Project = ProjectFingerprint(m.Project)
	}, func(m *PolicyMaterial) { m.Affected++ }, func(m *PolicyMaterial) {
		m.Project.ManifestSHA256 = strings.Repeat("5", 64)
		m.Scope.Project = ProjectFingerprint(m.Project)
	}} {
		q := m
		mutate(&q)
		if AcceptanceFingerprint(q) == initial {
			t.Fatal("evidence change ignored")
		}
	}
	for _, mutate := range []func(*PolicyMaterial){func(m *PolicyMaterial) { m.Observation = 99 }, func(m *PolicyMaterial) { m.Scope.Origin = "https://other.invalid/file" }, func(m *PolicyMaterial) { m.Project.Lock = 2 }, func(m *PolicyMaterial) { m.Profile = "unknown" }, func(m *PolicyMaterial) { m.Scope.Class = "installed" }, func(m *PolicyMaterial) { m.Expected = EvidenceSide{State: "absent", Type: "none"} }} {
		q := m
		mutate(&q)
		if ValidatePolicyMaterial(p, inv, nil, ds, q) == nil {
			t.Fatal("malformed/orphan admitted", q)
		}
	}
	if _, e := EvaluatePolicy(p, nil, inv, ds, []PolicyMaterial{m, m}, false, matchingNow); e == nil {
		t.Fatal("duplicate material")
	}
	empty := EvidenceSide{State: "present", Type: "file", SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	absent := EvidenceSide{State: "absent", Type: "none"}
	if !sideShape(empty) || !sideShape(absent) || policyFingerprint("side", empty) == policyFingerprint("side", absent) {
		t.Fatal("empty/absent collapsed")
	}
}
