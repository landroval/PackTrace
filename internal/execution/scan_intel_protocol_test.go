package execution

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestScanIntelligenceIPCRequiresExactlyOneBoundStateAndClosure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned local protocol process")
	}
	for _, mode := range []string{"intel-valid", "intel-missing", "intel-duplicate", "intel-bad-closure", "intel-wrong-id"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			p := integrityscan.Policy{Version: 1, Designation: "user-designated", Reason: "fixture", Provenance: "fixture", Manager: "npm@10.9.4", RequiredChecks: []string{"integrity"}, FailOn: []string{}, MinimumAssurance: "lockfile-consistent", References: []integrityscan.Reference{{Location: "node_modules/p", LockKey: "node_modules/p", Name: "p", Version: "1.0.0", Origin: "fixture:p", Classification: "unknown", ExpectedSRI: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Archive: "p.tgz", Context: "none"}}}
			plan := integrityscan.Plan{Manager: p.Manager, Policy: p, Checks: 4}
			s := newRunState(ctx)
			run := ScanRun{Plan: plan, Usable: true, output: BatchRun{state: s}}
			cmd := exec.Command(os.Args[0], "--scan-fault-driver", mode)
			identity, e := buildIdentity()
			if e != nil {
				t.Fatal(e)
			}
			cfg := scanConfig{Stage: "acquire", Target: t.TempDir(), PolicyPath: filepath.Join(t.TempDir(), "policy.json"), PolicyHash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Plan: &plan, Intelligence: &scanIntelligenceConfig{Generation: strings.Repeat("1", 64), Selection: "current"}}
			_, e = run.superviseScanPhase(ctx, cfg, cmd, identity)
			_, finish := run.Finish()
			if mode == "intel-valid" {
				if e != nil || finish != nil || run.Intelligence == nil {
					t.Fatal("positive IPC control", e, finish)
				}
				return
			}
			if e == nil || cmd.ProcessState == nil || run.Summary.Qualified || run.Summary.AuthorityComplete {
				t.Fatal("unbound/missing/duplicate intelligence frame accepted", e, cmd.ProcessState)
			}
		})
	}
}
func scanIntelFixture(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "state")
	input, e := filepath.Abs("testdata/intel/owned.bundle")
	if e != nil {
		t.Fatal(e)
	}
	run, e := RunIntel(ctx, cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelImport, StateDir: state, Input: input, Format: "json"})
	_, close := run.Finish()
	if e != nil || close != nil || !run.Usable || run.Result.Outcome != "complete" {
		t.Fatal("actual import", e, close)
	}
	return t.TempDir(), state
}
func TestScanIntelligenceCloseFailureStaysIncompleteAcrossFinish(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native original metadata")
	}
	t.Parallel()
	ctx := context.Background()
	target, state := scanIntelFixture(t)
	owner, e := openScanIntelligence(ctx, target, state, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	s := newRunState(ctx)
	s.scan = newScanLifecycle(ctx, s.deadline)
	s.intelligence = owner
	run := ScanRun{output: BatchRun{state: s}}
	if e := owner.metadata.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := run.Finish(); e == nil {
		t.Fatal("lost original metadata became complete cleanup")
	}
	if _, e := run.Finish(); e == nil {
		t.Fatal("second Finish erased original close/revalidation failure")
	}
}
func TestScanIntelligenceWorkerUsesFixedGenerationAfterSelectorMutation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native roots")
	}
	t.Parallel()
	ctx := context.Background()
	target, state := scanIntelFixture(t)
	parent, e := openScanIntelligence(ctx, target, state, "", nil)
	if e != nil || parent.pin == nil {
		t.Fatal(e)
	}
	defer parent.close()
	writer, e := nativefs.OpenOwnedDirectory(ctx, state, false)
	if e != nil {
		t.Fatal(e)
	}
	lease, e := writer.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	f, e := writer.CopyExclusive(ctx, "activation/corruption-control", bytes.NewReader([]byte("invalid selector")), 32)
	if e != nil {
		t.Fatal(e)
	}
	if e := writer.Publish(ctx, f, "activation/current.json", true); e != nil {
		t.Fatal(e)
	}
	f.Close()
	lease.Close()
	writer.Close()
	child, info, e := workerScanIntelligence(ctx, target, parent.cfg)
	if child != nil {
		defer child.close()
	}
	if e != nil || info.State != "available" || info.ID != parent.cfg.Generation {
		t.Fatal("worker reread changed selector instead of original controller-pinned generation", info, e)
	}
	id := parent.pin.ID()
	cfg := parent.cfg
	cfg.TrustedDigest = "sha256-" + base64.StdEncoding.EncodeToString(id[:])
	cfg.Selection = "expected-digest"
	cfg.NowUnixNS = time.Now().Add(8 * 24 * time.Hour).UnixNano()
	aged, expired, e := workerScanIntelligence(ctx, target, cfg)
	if aged != nil {
		defer aged.close()
	}
	if e != nil || expired.State != "available" || expired.CheckAge != "expired" || expired.ReconciliationAge != "expired" || expired.Provenance != "operator-designated" {
		t.Fatal("readonly source renewed an expired acquisition", expired, e)
	}
	cfg.NowUnixNS = time.Now().Add(-365 * 24 * time.Hour).UnixNano()
	future, unknown, e := workerScanIntelligence(ctx, target, cfg)
	if future != nil {
		defer future.close()
	}
	if e != nil || unknown.State != "available" || unknown.CheckAge != "unknown" || unknown.ReconciliationAge != "unknown" {
		t.Fatal("future source dates survived controller clock rollback", unknown, e)
	}
}
func TestScanIntelligenceRootReplacementCannotRebindControllerPin(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native roots")
	}
	t.Parallel()
	ctx := context.Background()
	target, state := scanIntelFixture(t)
	parent, e := openScanIntelligence(ctx, target, state, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer parent.close()
	if e := os.Rename(target, target+"-retained"); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(target + "-retained")
	if e := os.Mkdir(target, 0700); e != nil {
		t.Fatal(e)
	}
	child, _, e := workerScanIntelligence(ctx, target, parent.cfg)
	if child != nil {
		defer child.close()
	}
	if e == nil {
		t.Fatal("equal pathname replaced retained original target")
	}
}
