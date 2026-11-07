package execution

import (
	"context"
	"os"
	"packtrace/internal/cli"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIntelActualOfflineImportStatusPinExportReimportAndPreview(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native worker")
	}
	ctx := context.Background()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	fixture, e := filepath.Abs("testdata/intel/owned.bundle")
	if e != nil {
		t.Fatal(e)
	}
	call := func(r cli.IntelArgumentRequest) IntelResult {
		t.Helper()
		r.StateDir = state
		r.Format = "terminal"
		run, e := RunIntel(ctx, r)
		receipt, finish := run.Finish()
		if e != nil || finish != nil || !run.Usable || run.Result.Outcome != "complete" || !receipt.CleanupConfirmed {
			t.Fatal("actual operation failed", r.Action, run.Result, e, finish)
		}
		return run.Result
	}
	imported := call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelImport, Input: fixture})
	if imported.Observation == nil || imported.Observation.SourceAuthority != "unqualified" {
		t.Fatal("import self-authorized freshness")
	}
	id := imported.Generation
	call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus})
	call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelPin, Generation: id})
	call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelUnpin, Generation: id})
	output := filepath.Join(base, "output.bundle")
	exported := call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelExport, Output: output})
	info, e := os.Stat(output)
	if e != nil || uint64(info.Size()) != exported.WrittenBytes {
		t.Fatal("no actual published transport", e)
	}
	state = filepath.Join(base, "second-state")
	second := call(cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelImport, Input: output})
	if second.Generation != id {
		t.Fatal("descriptor identity changed across actual workers")
	}
	preview := call(cli.IntelArgumentRequest{Action: cli.ArgumentActionCachePrune})
	if preview.Preview == nil {
		t.Fatal("no actual preview")
	}
}
