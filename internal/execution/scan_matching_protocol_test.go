package execution

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

func matchingFaultFrames(c *channel, cfg scanConfig, mode string) int {
	info := integrityscan.UnavailableIntelligence()
	_ = c.send("intel-state", info)
	_ = c.send("intel-closure", scanIntelligenceClosure{1})
	p := projectinventory.PublicInventory{
		Scopes:       []projectinventory.PublicScope{{ID: 1, Kind: "project", Status: "incomplete"}},
		Evidence:     []projectinventory.PublicEvidence{{ID: 1, Scope: 1, Method: "native-metadata", Status: "incomplete"}, {ID: 2, Scope: 1, Method: "native-input-lease", Status: "complete"}},
		Observations: []projectinventory.PublicObservation{{ID: 1, Workspace: 1, Source: 2, Class: "locked", Kind: "url", Status: "complete"}},
		Relations:    []projectinventory.Relation{}, Gaps: []projectinventory.Gap{{Scope: 1, Evidence: 1, Code: "discovery-incomplete"}},
		Selection: projectinventory.PublicSelection{Family: "npm", State: "usable", Reason: "none"},
		Counts:    projectinventory.Counters{Scopes: 1, Evidence: 2, Locked: 1, Gaps: 1},
	}
	batches := uint32(0)
	if projectinventory.WalkBatches(p, func(b projectinventory.InventoryBatch) error { batches++; return c.send("inventory-batch", b) }) != nil {
		return 91
	}
	_ = c.send("inventory-closure", scanInventoryClosure{Batches: batches, Selection: p.Selection, Counts: p.Counts})
	if strings.HasPrefix(mode, "matching-local-") {
		observation := integrityscan.LocalObservation{Observation: 1, Name: "left-pad", Version: "1.0.0", Location: "node_modules/left-pad"}
		if mode == "matching-local-absolute" {
			observation.Location = "/PRIVATE-absolute"
		}
		_ = c.send("local-observations", scanLocalObservations{Observations: []integrityscan.LocalObservation{observation}})
		if mode != "matching-local-missing-closure" {
			count := 1
			if mode == "matching-local-bad-count" {
				count = 2
			}
			_ = c.send("local-closure", scanLocalClosure{Batches: 1, Observations: count})
		}
	}
	d := integrityscan.AdvisoryDecision{Observation: 1, Affected: -1, VersionOutcome: "indeterminate", Outcome: "indeterminate", Category: "unknown", Profile: "unknown", Activity: "unknown", Origin: "unqualified", Source: "unqualified", Support: []integrityscan.AdvisorySupport{}, Gaps: []string{"origin-unqualified", "source-unqualified", "intelligence-unavailable"}}
	s := integrityscan.AdvisorySummary{Decisions: 1, Observations: 1, TotalObservations: 1, Work: 1, Gaps: []string{"declared-unassessed", "index-completeness", "inventory-incomplete"}}
	switch mode {
	case "matching-bad-source":
		d.Source = "qualified"
	case "matching-bad-eligibility":
		d.EnforcementEligible = true
	case "matching-candidate-unsolicited":
		d.Candidate = true
	case "matching-assessment-unsolicited":
		d.Advisory, d.Affected, d.VersionOutcome = 1, 0, "no-match"
	case "matching-private-gap":
		d.Gaps = append(d.Gaps, "PRIVATE-untrusted-error")
	case "matching-wrong-observation":
		d.Observation = 2
	case "matching-bad-sequence":
		d.Sequence = 1
	case "matching-problem-unbound":
		d.FirstVersionProblem = &integrityscan.AdvisoryVersionProblem{Scope: "affected", Kind: "version-outside-profile", Version: 0, Range: -1, Event: -1}
	case "matching-problem-private-kind":
		d.FirstVersionProblem = &integrityscan.AdvisoryVersionProblem{Scope: "affected", Kind: "PRIVATE-untrusted-condition", Version: -1, Range: -1, Event: -1}
	}
	if mode == "matching-zero-work-limit" {
		s.Decisions, s.Observations, s.Work = 0, 0, 0
		s.Gaps = append(s.Gaps, "evaluation-limit")
	} else {
		_ = c.send("matching-decision", d)
	}
	if mode == "matching-duplicate-decision" {
		d.Sequence = 1
		_ = c.send("matching-decision", d)
	}
	if mode == "matching-bad-count" {
		s.Decisions++
	}
	if mode != "matching-missing-closure" {
		_ = c.send("matching-closure", s)
	}
	if mode == "matching-duplicate-closure" {
		_ = c.send("matching-closure", s)
	}
	if mode == "matching-late-decision" {
		d.Sequence = 1
		_ = c.send("matching-decision", d)
	}
	_ = c.send("done", scanDone{})
	if mode == "matching-after-done" {
		_ = c.send("matching-closure", s)
	}
	if mode == "matching-crash-after-closure" {
		return 7
	}
	return 0
}

func TestMatchingProtocolRequiresExactClosedParentScope(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local process controls")
	}
	// Independent owned streams can share the test runner's existing bounded
	// parallelism; race-runtime teardown need not serialize fourteen children.
	t.Parallel()
	for _, mode := range []string{"matching-valid", "matching-bad-source", "matching-bad-eligibility", "matching-candidate-unsolicited", "matching-assessment-unsolicited", "matching-private-gap", "matching-wrong-observation", "matching-bad-sequence", "matching-problem-unbound", "matching-problem-private-kind", "matching-duplicate-decision", "matching-bad-count", "matching-zero-work-limit", "matching-missing-closure", "matching-duplicate-closure", "matching-late-decision", "matching-after-done", "matching-crash-after-closure", "matching-local-valid", "matching-local-unsolicited", "matching-local-missing-closure", "matching-local-absolute", "matching-local-bad-count"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: "npm@10.9.4", RequiredChecks: []string{"malicious"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
			plan := integrityscan.Plan{Manager: p.Manager, Policy: p, Checks: cli.ArgumentCheckMalicious}
			if strings.HasPrefix(mode, "matching-local-") && mode != "matching-local-unsolicited" {
				plan.Privacy = "local"
			}
			s := newRunState(ctx)
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: s}}
			cmd := exec.Command(os.Args[0], "--scan-fault-driver", mode)
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan, Intelligence: &scanIntelligenceConfig{}}
			_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
			if (e == nil) != (mode == "matching-valid" || mode == "matching-local-valid") || cmd.ProcessState == nil {
				t.Fatalf("protocol outcome: %v state=%v", e, cmd.ProcessState)
			}
			closed := mode == "matching-valid" || mode == "matching-local-valid" || mode == "matching-duplicate-closure" || mode == "matching-late-decision" || mode == "matching-after-done" || mode == "matching-crash-after-closure"
			if closed != (run.Advisories != nil) {
				t.Fatal("unclosed rows promoted or closed partial evidence lost", run.Advisories)
			}
			if mode == "matching-local-valid" && (run.Advisories == nil || run.Advisories.Local == nil || len(run.Advisories.Local.Observations) != 1) {
				t.Fatal("explicit local closed evidence lost")
			}
			if run.Advisories != nil && (len(run.Advisories.Decisions) != 1 || run.Advisories.Findings != 0 || run.Advisories.Decisions[0].Outcome != "indeterminate") {
				t.Fatal("protocol controls invented an eligible finding")
			}
			if e != nil && strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("untrusted protocol error leaked")
			}
		})
	}
}
