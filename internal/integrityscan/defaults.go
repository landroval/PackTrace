package integrityscan

import (
	"path/filepath"
	"reflect"

	"packtrace/internal/cli"
)

// ConfigureBuiltin constructs in-memory, no-grants defaults; it never discovers
// configuration or supplies an authenticated producer identity.
func ConfigureBuiltin(r cli.ScanArgumentRequest) (Plan, error) {
	return configureSource(r, Policy{}, true)
}
func configureBuiltin(r cli.ScanArgumentRequest) (Plan, error) {
	if r.Privacy == "" {
		r.Privacy = "portable"
	}
	all := cli.ArgumentCheckIntegrity | cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
	if r.PolicyPath != "" || r.TrustedPolicyDigest != "" || !oneOf(r.Manager, "auto", "npm", "bun") && !profile(r.Manager) || !oneOf(r.Privacy, "portable", "local") || r.Output == "" || r.Checks == 0 || r.Checks & ^all != 0 || r.FailOn & ^r.Checks != 0 || r.StateDir != "" && !filepath.IsAbs(r.StateDir) || r.TrustedSnapshotDigest != "" && !supportedSnapshotPin(r.TrustedSnapshotDigest) {
		return Plan{}, ErrOptions
	}
	p := Policy{Version: 1, Designation: "built-in", Manager: r.Manager, RequiredChecks: []string{}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []Reference{}}
	return Plan{Builtin: true, Provided: r.Provided, Manager: r.Manager, ExplicitManager: r.Manager != "auto", Checks: r.Checks, FailOn: r.FailOn, Policy: p, Privacy: r.Privacy, StateDir: r.StateDir, TrustedSnapshotDigest: r.TrustedSnapshotDigest}, nil
}

// ValidatePlanPolicy admits only exact recomputed built-ins, or the existing
// explicit-policy source with independently pinned grants.
func ValidatePlanPolicy(p Plan) error {
	r := cli.ScanArgumentRequest{Manager: p.Manager, Privacy: p.Privacy, PolicyPath: p.PolicyFile, TrustedPolicyDigest: p.TrustedPolicyDigest, StateDir: p.StateDir, TrustedSnapshotDigest: p.TrustedSnapshotDigest, Checks: p.Checks, FailOn: p.FailOn, Provided: p.Provided, Output: "-"}
	var want Plan
	var err error
	if p.Builtin {
		want, err = ConfigureBuiltin(r)
	} else {
		if p.PolicyFile == "" || filepath.Base(p.PolicyFile) != p.PolicyFile {
			return ErrPolicy
		}
		// Preserve explicit acquisition helper semantics: unpinned independent
		// assurance can still produce an honest binding gap. Configure owns CLI
		// admission; the existing native reread/pin helpers remain authoritative.
		required, _ := categories(p.Policy.RequiredChecks)
		fail, _ := categories(p.Policy.FailOn)
		all := cli.ArgumentCheckIntegrity | cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability
		if ValidatePolicy(p.Policy) != nil || p.Manager != p.Policy.Manager || p.Checks & ^all != 0 || required & ^p.Checks != 0 || fail & ^p.FailOn != 0 || p.FailOn & ^p.Checks != 0 || !oneOf(p.Privacy, "", "portable", "local") || p.Policy.RequirePortable && p.Privacy == "local" || (len(p.Policy.Exceptions) != 0 || p.Policy.MaxExceptionDays != 0) && !supportedPolicyPin(p.TrustedPolicyDigest) {
			return ErrPolicy
		}
		return nil
	}
	if err != nil || !reflect.DeepEqual(want, p) {
		return ErrPolicy
	}
	return nil
}
