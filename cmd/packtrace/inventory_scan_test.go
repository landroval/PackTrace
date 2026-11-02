package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/projectinventory"
)

func TestActualScanInventoryIsCommonAndPrivateAcrossFormats(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned Linux/Windows scan")
	}
	for _, mode := range []string{"version-conflict", "no-lock", "missing-installed-manifest", "workspace"} {
		t.Run(mode, func(t *testing.T) {
			root, policy := scanFixture(t)
			for name, body := range map[string]string{"package.json": `{"dependencies":{"PRIVATE-pkg":"^1"}}`, "node_modules/PRIVATE-pkg/package.json": `{"name":"PRIVATE-pkg","version":"2.0.0"}`, "node_modules/PRIVATE-extra/package.json": `{"name":"PRIVATE-extra","version":"1.0.0"}`} {
				full := filepath.Join(root, filepath.FromSlash(name))
				if os.MkdirAll(filepath.Dir(full), 0700) != nil || os.WriteFile(full, []byte(body), 0600) != nil {
					t.Fatal("owned fixture")
				}
			}
			lock := filepath.Join(root, "package-lock.json")
			data, e := os.ReadFile(lock)
			if e != nil {
				t.Fatal(e)
			}
			data = bytes.Replace(data, []byte(`"":{}`), []byte(`"":{"dependencies":{"PRIVATE-pkg":"^1"}}`), 1)
			if os.WriteFile(lock, data, 0600) != nil {
				t.Fatal("fixture lock")
			}
			locked, installed, scopes := 2, 2, 1
			complete := mode == "version-conflict" || mode == "workspace"
			if mode == "workspace" {
				for name, body := range map[string]string{"package.json": `{"dependencies":{"PRIVATE-pkg":"^1"},"workspaces":["packages/*"]}`, "packages/member/package.json": `{}`, "packages/member/node_modules/PRIVATE-member-dep/package.json": `{"name":"PRIVATE-member-dep","version":"1.0.0"}`} {
					full := filepath.Join(root, filepath.FromSlash(name))
					if os.MkdirAll(filepath.Dir(full), 0700) != nil || os.WriteFile(full, []byte(body), 0600) != nil {
						t.Fatal("owned workspace fixture")
					}
				}
				installed, scopes = 3, 2
			}
			if mode == "no-lock" {
				if os.Remove(lock) != nil {
					t.Fatal("owned absent lock")
				}
				locked = 0
			}
			if mode == "missing-installed-manifest" {
				if os.Remove(filepath.Join(root, "node_modules/PRIVATE-extra/package.json")) != nil {
					t.Fatal("owned missing manifest")
				}
			}
			for _, format := range []string{"terminal", "json", "sarif"} {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--checks", "integrity", "--format", format, root)
				var out, diag bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &diag
				e := cmd.Run()
				cancel()
				if e == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 || strings.Contains(out.String()+diag.String(), "PRIVATE") {
					t.Fatalf("actual inventory output/reap/privacy %s %s: %v %v %s", mode, format, e, cmd.ProcessState, diag.String())
				}
				if format == "terminal" {
					want := fmt.Sprintf("Inventory: declared=1 locked=%d installed=%d", locked, installed)
					if !strings.Contains(out.String(), want) {
						t.Fatal("terminal inventory omitted", out.String())
					}
					continue
				}
				var report map[string]json.RawMessage
				if format == "json" {
					if json.Unmarshal(out.Bytes(), &report) != nil {
						t.Fatal("json")
					}
				} else {
					var sarif struct {
						Runs []struct {
							Properties map[string]json.RawMessage `json:"properties"`
						} `json:"runs"`
					}
					if json.Unmarshal(out.Bytes(), &sarif) != nil || len(sarif.Runs) != 1 {
						t.Fatal("sarif")
					}
					report = sarif.Runs[0].Properties
				}
				var schema string
				_ = json.Unmarshal(report["schemaVersion"], &schema)
				var inv projectinventory.PublicInventory
				if schema != "1.1" || json.Unmarshal(report["inventory"], &inv) != nil || projectinventory.ValidatePublic(inv) != nil || inv.Counts.Declared != 1 || inv.Counts.Locked != locked || inv.Counts.Installed != installed || inv.Counts.Scopes != scopes || inv.Complete != complete {
					t.Fatalf("common inventory model omitted or promoted: %s", out.String())
				}
				if mode == "version-conflict" {
					found := false
					for _, r := range inv.Relations {
						found = found || r.Kind == "locked-correspondence" && r.Status == "conflict"
					}
					if !found {
						t.Fatal("version disagreement lost", inv.Relations)
					}
				}
			}
		})
	}
}
