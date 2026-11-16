package execution

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
)

func TestSelectedAdvisoryScopeCannotBeGrantedByChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local protocol process controls, not platform qualification")
	}
	for _, mode := range []string{"matching-valid", "matching-scope-gap-deletion", "matching-scope-child-completed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			policy := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious", "vulnerability"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
			plan := integrityscan.Plan{Manager: policy.Manager, Policy: policy, Checks: cli.ArgumentCheckMalicious | cli.ArgumentCheckVulnerability}
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: newRunState(ctx)}}
			cmd := exec.Command(os.Args[0], "--scan-fault-driver", mode)
			identity, err := buildIdentity()
			if err != nil {
				t.Fatal(err)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan, Intelligence: &scanIntelligenceConfig{}}
			_, err = run.superviseScanPhase(ctx, cfg, cmd, identity)
			if (err == nil) != (mode == "matching-valid") {
				t.Fatal("child granted scope or baseline lost", mode, err)
			}
			if run.Advisories != nil && run.Advisories.SelectedScope != nil {
				t.Fatal("child receipt retained without independent originals")
			}
		})
	}
}
