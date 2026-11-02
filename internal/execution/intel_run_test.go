package execution

import (
	"context"
	"os"
	"packtrace/internal/cli"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIntelActualWorkerUnavailableStatusNeverInitializes(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("retained process backend")
	}
	path := filepath.Join(t.TempDir(), "absent")
	run, e := RunIntel(context.Background(), cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: path, Format: "json"})
	receipt, finish := run.Finish()
	if e != nil || finish != nil || !run.Usable || run.Result.Outcome != "unavailable" || !receipt.CleanupConfirmed || len(receipt.Roles) != 1 || !receipt.Roles[0].Reaped {
		t.Fatal("actual fixed worker failed", run.Result, e, finish, receipt)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("status initialized missing store", e)
	}
}
func TestIntelActualPublicWriterRetainsPreparationRoleAndReaps(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native observer")
	}
	run, e := RunIntel(context.Background(), cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelStatus, StateDir: filepath.Join(t.TempDir(), "absent"), Format: "json"})
	if e != nil {
		run.Finish()
		t.Fatal(e)
	}
	file, e := os.CreateTemp(t.TempDir(), "output")
	if e != nil {
		run.Finish()
		t.Fatal(e)
	}
	defer file.Close()
	e = run.WriteOutput(context.Background(), file, []byte("owned output"))
	receipt, finish := run.Finish()
	if e != nil || finish != nil || len(receipt.Roles) != 2 || receipt.Roles[1].Role != "intel-writer" || !receipt.Roles[1].Reaped {
		t.Fatal("wrong preparation writer lifecycle", e, finish, receipt)
	}
}
func TestIntelRequestCannotSmuggleTargetIntoSync(t *testing.T) {
	run, e := RunIntel(context.Background(), cli.IntelArgumentRequest{Action: cli.ArgumentActionIntelSync, StateDir: "private", Input: "private-project", Format: "json"})
	run.Finish()
	if e == nil {
		t.Fatal("target accepted by preparation source request")
	}
}
