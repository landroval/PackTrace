package execution

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
)

// Deliberate protocol faults in an owned test process. No synthetic record
// asserts native acquisition success: the only retained receipt is a binding gap.
func scanFaultDriver(mode string) int {
	c := newChannel(os.Stdin, os.Stdout, &traffic{})
	identity, e := buildIdentity()
	if e != nil {
		return 98
	}
	if mode == "wrong-build" {
		identity = "wrong"
	}
	if c.send("hello", hello{identity}) != nil {
		return 97
	}
	var h hello
	var cfg scanConfig
	if c.expect("hello", &h) != nil || c.expect("config", &cfg) != nil {
		return 96
	}
	if _, e = c.receive(); e != io.EOF {
		return 95
	}
	if mode == "empty-exit" {
		return 0
	}
	_ = c.send("start", scanStart{cfg.Stage})
	if mode != "missing-resident" {
		rss, e := nativefs.OwnResidentBytes()
		if e != nil {
			return 94
		}
		_ = c.send("resident", residentSample{ElapsedMS: 0, Bytes: rss, Valid: true})
	}
	if mode == "policy-pin-forgery" {
		p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "owned", Provenance: "owned", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{}}
		_ = c.send("policy", integrityscan.PolicyObservation{Policy: p, SourceHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", MatchedOperatorDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
		_ = c.send("done", scanDone{})
		return 0
	}
	if mode == "oversize" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("X", maxMessage+1))
		return 0
	}
	if cfg.Stage == "acquire" {
		sendFaultInventory(c, mode)
	}
	r := integrityscan.Record{Index: 0, Assessment: integrity.InstanceAssessment{InstanceID: "instance-1", Differences: []integrity.Difference{}, Contexts: []integrity.ScopedContext{}, Gaps: []integrity.Gap{{Code: integrity.GapBinding, InstanceID: "instance-1"}}}}
	if mode == "forged-completion" {
		r.Assessment.SuppliedComparisonComplete = true
	}
	_ = c.send("instance", r)
	if mode == "crash-before-closure" {
		return 7
	}
	closure := scanClosure{Index: 0, Gaps: 1}
	if mode == "wrong-closure" {
		closure.Gaps = 0
	}
	_ = c.send("closure", closure)
	if mode == "duplicate-closure" {
		_ = c.send("closure", closure)
	}
	summary := integrityscan.Summary{Records: 1}
	if mode == "native-authority-forgery" {
		summary.Qualified = true
		summary.AuthorityComplete = true
	}
	if mode == "reference-authority-forgery" {
		summary.AuthorityComplete = true
	}
	_ = c.send("done", scanDone{Records: 1, Summary: summary})
	switch mode {
	case "done-crash":
		return 7
	case "extra":
		_ = c.send("done", scanDone{})
	case "done-stall":
		time.Sleep(20 * time.Second)
	case "done-observation-window":
		time.Sleep(450 * time.Millisecond)
	}
	return 0
}

// Removing retained observation through process exit makes this fail under -race:
// the runtime stays resident for a second after the protocol's final done.
func TestScanCompletedWorkerRuntimeTeardownIsObserved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local Linux process check only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := newRunState(ctx)
	run := ScanRun{output: BatchRun{state: s}}
	cmd := exec.Command(os.Args[0], "--scan-fault-driver", "done-observation-window")
	identity, e := buildIdentity()
	if e != nil {
		t.Fatal(e)
	}
	// Use the existing acquire fixture, then retain a controlled live interval
	// after done AND the race runtime's additional post-main teardown.
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "fixture", Provenance: "fixture", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/p", LockKey: "node_modules/p", Name: "p", Version: "1.0.0", Origin: "fixture:p", Classification: "unknown", ExpectedSRI: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Archive: "p.tgz", Context: "none"}}}
	plan := integrityscan.Plan{Manager: p.Manager, Policy: p, Checks: 4}
	cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan}
	_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
	if e != nil || cmd.ProcessState == nil || !cmd.ProcessState.Success() || len(run.Records) != 1 {
		t.Fatalf("completed process teardown lost: %v state=%v records=%d resources=%+v", e, cmd.ProcessState, len(run.Records), run.Resources)
	}
	receipt := s.scan.snapshot()
	if len(receipt.Roles) != 1 || receipt.Roles[0].Samples < 4 || !receipt.Roles[0].ExitObserved || !receipt.Roles[0].Reaped || !receipt.Finished || !receipt.CleanupConfirmed {
		t.Fatalf("post-done process lifetime not observed: %+v", receipt)
	}
	t.Logf("actual post-done/runtime-teardown receipt: %+v roles=%+v", receipt, receipt.Roles)
}

func TestPolicyPinAttestationCannotGrantOrChangeParentTrust(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local process negative")
	}
	for _, pin := range []string{"", "sha384-" + strings.Repeat("A", 64)} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		s := newRunState(ctx)
		run := ScanRun{output: BatchRun{state: s}}
		cmd := exec.Command(os.Args[0], "--scan-fault-driver", "policy-pin-forgery")
		identity, e := buildIdentity()
		if e != nil {
			cancel()
			t.Fatal("identity")
		}
		cfg := scanConfig{Stage: "policy", Target: t.TempDir(), PolicyPath: t.TempDir() + "/policy.json", TrustedPolicyDigest: pin}
		_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
		cancel()
		if e == nil || cmd.ProcessState == nil || run.Summary.AuthorityComplete || run.Summary.Qualified {
			t.Fatal("worker granted or replaced parent policy trust")
		}
	}
}

func TestScanFaultChildrenCannotAuthorizeCompletion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local Linux process checks only")
	}
	p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "fixture", Provenance: "fixture", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/p", LockKey: "node_modules/p", Name: "p", Version: "1.0.0", Origin: "fixture:p", Classification: "unknown", ExpectedSRI: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Archive: "p.tgz", Context: "none"}}}
	plan := integrityscan.Plan{Manager: p.Manager, Policy: p, Checks: 4}
	for _, tc := range []struct {
		mode     string
		retained int
	}{{"wrong-build", 0}, {"empty-exit", 0}, {"oversize", 0}, {"forged-completion", 0}, {"wrong-closure", 0}, {"crash-before-closure", 0}, {"done-crash", 1}, {"duplicate-closure", 1}, {"extra", 1}, {"native-authority-forgery", 1}, {"reference-authority-forgery", 1}, {"missing-resident", 1}, {"done-stall", 1}} {
		t.Run(tc.mode, func(t *testing.T) {
			timeout := 3 * time.Second
			if tc.mode == "done-stall" {
				timeout = 250 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			s := newRunState(ctx)
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: s}}
			cmd := exec.Command(os.Args[0], "--scan-fault-driver", tc.mode)
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: t.TempDir() + "/p.json", PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan}
			_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
			if e == nil || len(run.Records) != tc.retained || cmd.ProcessState == nil || run.Summary.Qualified || run.Summary.AuthorityComplete {
				t.Fatalf("fault accepted/leaked/escaped reap %s: %+v %v", tc.mode, run, e)
			}
			report := integrityscan.BuildReport(plan, run.Records, run.Summary, run.Resources, false, true)
			if report.ExitCode != 3 {
				t.Fatal("worker chose public success", report)
			}
		})
	}
}
