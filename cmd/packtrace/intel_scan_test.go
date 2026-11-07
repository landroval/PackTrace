package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"packtrace/internal/cli"
	"packtrace/internal/execution"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func ownedIntelScanState(t *testing.T) (string, intelstore.ID) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "PRIVATE-state")
	return path, importIntelScanFixture(t, path)
}
func importIntelScanFixture(t *testing.T, path string) intelstore.ID {
	t.Helper()
	ctx := context.Background()
	source, e := filepath.Abs("../../internal/execution/testdata/intel")
	if e != nil {
		t.Fatal(e)
	}
	root, e := nativefs.OpenRoot(ctx, source)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	input, e := root.OpenDistributionInput(ctx, "owned.bundle")
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	store, e := intelstore.Open(ctx, path, intelstore.CreateOwned)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	received, e := store.Import(ctx, input, intelstore.ImportOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return received.Generation
}
func TestScanCorruptOrFallbackSourceNeverRepairsOrClaimsMatching(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native reader")
	}
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "corrupt", true: "previous-fallback"}[fallback], func(t *testing.T) {
			state, id := ownedIntelScanState(t)
			target, policy := scanFixture(t)
			if fallback {
				if other := importIntelScanFixture(t, state); other != id {
					t.Fatal("repeat import changed descriptor")
				}
			}
			damaged := filepath.Join(state, "generations", hex.EncodeToString(id[:]), "sealed.json")
			if fallback {
				damaged = filepath.Join(state, "activation", "current.json")
			}
			if e := os.WriteFile(damaged, []byte("owned corruption canary"), 0600); e != nil {
				t.Fatal(e)
			}
			var out, diag bytes.Buffer
			code := runMain([]string{"scan", "--policy", policy, "--checks", "integrity", "--state-dir", state, "--format", "json", target}, forbiddenReader{}, &out, &diag)
			if code != 3 || diag.Len() != 0 {
				t.Fatal("source damage displaced integrity", code, out.String(), diag.String())
			}
			var report struct {
				Findings     int `json:"findings"`
				Intelligence struct {
					State, Selection, Provenance, CheckAge string
					Gaps                                   []string
				} `json:"intelligence"`
			}
			if json.Unmarshal(out.Bytes(), &report) != nil || report.Findings != 1 {
				t.Fatal("source damage erased integrity", out.String())
			}
			if fallback {
				if report.Intelligence.State != "available" || report.Intelligence.Selection != "previous-fallback" || report.Intelligence.Provenance != "unqualified" || report.Intelligence.CheckAge != "unknown" {
					t.Fatal("fallback/import elevated trust", out.String())
				}
			} else if report.Intelligence.State != "unavailable" {
				t.Fatal("corrupt source admitted", out.String())
			}
			if bytes, e := os.ReadFile(damaged); e != nil || string(bytes) != "owned corruption canary" {
				t.Fatal("readonly scan repaired state", e)
			}
		})
	}
}
func TestScanSnapshotPinSurvivesComparisonAndStalledOutputUntilFinish(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native original leases")
	}
	ctx := context.Background()
	state, id := ownedIntelScanState(t)
	target, policy := scanFixture(t)
	request := cli.ScanArgumentRequest{Path: target, PolicyPath: policy, StateDir: state, Checks: cli.ArgumentCheckIntegrity, Manager: "auto", Format: "json", Privacy: "portable", Output: "-"}
	run, e := execution.RunScan(ctx, request)
	defer run.Finish()
	if e != nil || run.Intelligence == nil || run.Intelligence.State != "available" {
		t.Fatal("actual pinned scan failed", run.Intelligence, e)
	}
	owned, e := nativefs.OpenOwnedDirectory(ctx, state, false)
	if e != nil {
		t.Fatal(e)
	}
	defer owned.Close()
	lockPath := "generations/" + hex.EncodeToString(id[:]) + "/read.lock"
	assertBusy := func() {
		t.Helper()
		exclusive, e := owned.ReadRoot().TryOwnedLock(ctx, lockPath, true)
		if e == nil {
			exclusive.Close()
			t.Fatal("controller released ORIGINAL source lease before Finish")
		}
	}
	assertBusy()
	// A second actual maintenance process can preview while the controller's
	// original generation lease remains held; it cannot reclaim that snapshot.
	preview, previewErr := execution.RunIntel(ctx, cli.IntelArgumentRequest{Action: cli.ArgumentActionCachePrune, StateDir: state, Format: "json"})
	pruneReceipt, pruneFinish := preview.Finish()
	if previewErr != nil || pruneFinish != nil || !preview.Usable || preview.Result.Preview == nil || preview.Result.Preview.Generations != 0 || !pruneReceipt.CleanupConfirmed {
		t.Fatal("actual prune preview ignored live selected source", previewErr, pruneFinish, preview.Result)
	}
	assertBusy()
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	defer writer.Close()
	work, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	e = run.WriteOutput(work, writer, bytes.Repeat([]byte("approved bytes"), 100000))
	cancel()
	if e == nil {
		t.Fatal("unread pipe was not backpressured")
	}
	assertBusy()
	receipt, e := run.Finish()
	if e != nil || !receipt.CleanupConfirmed || len(receipt.Roles) != 3 || receipt.Roles[2].Role != "scan-writer" || !receipt.Roles[2].Reaped {
		t.Fatal("writer/original observer cleanup", e, receipt)
	}
	exclusive, e := owned.ReadRoot().TryOwnedLock(ctx, lockPath, true)
	if e != nil {
		t.Fatal("confirmed Finish did not release original pin", e)
	}
	exclusive.Close()
}
func TestScanPreparedSnapshotIsOfflinePrivateAndNotMatching(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native scan")
	}
	state, id := ownedIntelScanState(t)
	root, policy := scanFixture(t)
	for _, format := range []string{"terminal", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity,malicious,vulnerability", "--state-dir", state, "--trusted-snapshot-digest", "sha256-"+base64.StdEncoding.EncodeToString(id[:]), "--format", format, root)
			receipt := retainScanReceipt(t, cmd)
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			e := cmd.Run()
			if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 {
				t.Fatalf("prepared state scan: %v %v out=%s diag=%s receipt=%s", e, cmd.ProcessState, out.String(), diag.String(), receipt())
			}
			if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String(), "sha256-") {
				t.Fatal("private selectors or expected SRI leaked")
			}
			if !strings.Contains(out.String(), hex.EncodeToString(id[:])) || !strings.Contains(out.String(), "operator-designated") || !strings.Contains(out.String(), "bounded-npm-locked-evidence") {
				t.Fatal("prepared source identity or uncertainty lost", out.String())
			}
			if format == "json" {
				var report struct {
					SchemaVersion string `json:"schemaVersion"`
					Intelligence  struct {
						State, Selection, Provenance, CheckAge string
						Objects, Bytes, Reserved               *uint64
					} `json:"intelligence"`
					Findings int `json:"findings"`
				}
				if json.Unmarshal(out.Bytes(), &report) != nil || report.SchemaVersion != "1.3" || report.Intelligence.State != "available" || report.Intelligence.Selection != "expected-digest" || report.Findings != 1 || report.Intelligence.Objects != nil || report.Intelligence.Bytes != nil || report.Intelligence.Reserved != nil {
					t.Fatal("state changed integrity or invented storage occupation", out.String())
				}
			}
		})
	}
}
func TestScanWithMissingStateDoesNotInitialize(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native scan")
	}
	root, policy := scanFixture(t)
	state := filepath.Join(t.TempDir(), "absent")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--state-dir", state, "--format", "json", root)
	receipt := retainScanReceipt(t, cmd)
	var out, diag bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diag
	e := cmd.Run()
	if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 {
		t.Fatalf("missing intelligence displaced scan: state=%v error=%v out=%s diag=%s receipt=%s", cmd.ProcessState, e, out.String(), diag.String(), receipt())
	}
	if _, e := os.Lstat(state); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("scan initialized state", e)
	}
	var report struct {
		SchemaVersion string `json:"schemaVersion"`
		Intelligence  struct {
			State string `json:"state"`
		} `json:"intelligence"`
	}
	if json.Unmarshal(out.Bytes(), &report) != nil || report.SchemaVersion != "1.2" || report.Intelligence.State != "unavailable" {
		t.Fatal("missing source projection absent", out.String())
	}
	if strings.Contains(out.String()+diag.String(), "PRIVATE") {
		t.Fatal("portable scan leaked target/policy/state")
	}
}
