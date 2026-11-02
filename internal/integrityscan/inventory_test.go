package integrityscan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"packtrace/internal/projectinventory"
)

func TestAcquisitionUsesSelectedInventoryBeforeIntegrity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned native unit; other platforms exercised by native campaign")
	}
	root, policy, p := ownedFixture(t)
	for name, body := range map[string]string{"node_modules/pkg/package.json": `{"name":"pkg","version":"2.0.0"}`, "node_modules/extra/package.json": `{"name":"extra","version":"1.0.0"}`, "bun.lock": `{"lockfileVersion":1,"workspaces":{"":{}},"packages":{}}`} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(full), 0700) != nil || os.WriteFile(full, []byte(body), 0600) != nil {
			t.Fatal("fixture")
		}
	}
	plan, hash := fixturePlan(t, policy, p)
	plan.ExplicitManager = true
	closed := false
	records := 0
	summary, e := AcquireWithInventory(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error {
		if !closed {
			t.Fatal("integrity before closed inventory")
		}
		records++
		if r.Lock.PackageID != "pkg" || r.Lock.Version != "1.0.0" {
			t.Fatal("inventory selection/installed claim overwrote lock", r.Lock)
		}
		return nil
	}, func(r projectinventory.Result) error {
		closed = true
		if r.Selection.State != "usable" || r.Selection.Reason != "explicit-manager-conflict" || r.Model.Counts().Installed != 2 || r.Model.Counts().Locked != 2 {
			t.Fatal("real inventory omitted or selected independently", r)
		}
		if projectinventory.ValidatePublic(projectinventory.Portable(r)) != nil {
			t.Fatal("invalid inventory")
		}
		return nil
	})
	if e != nil || records != 1 || !summary.InventoryComplete || summary.Qualified {
		t.Fatal("shared acquisition failed/promoted native qualification", summary, e)
	}
}
