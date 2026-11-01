package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
)

func TestActualBundledOwnershipAndContextReports(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned supported native CLI")
	}
	for _, kind := range []string{"generated", "patch"} {
		t.Run(kind, func(t *testing.T) {
			root, policy := scanFixtureForBundle(t, true)
			data, e := os.ReadFile(policy)
			if e != nil {
				t.Fatal("policy")
			}
			var p integrityscan.Policy
			if json.Unmarshal(data, &p) != nil {
				t.Fatal("policy")
			}
			p.MinimumAssurance = "independently-anchored"
			p.References[0].Context = kind
			data, _ = json.Marshal(p)
			if os.WriteFile(policy, data, 0600) != nil {
				t.Fatal("policy")
			}
			h := sha256.Sum256(data)
			pin := "sha256-" + base64.StdEncoding.EncodeToString(h[:])
			for _, format := range []string{"json", "terminal", "sarif"} {
				t.Run(format, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSupervisedCLIProcess$", "--", "scan", "--policy", policy, "--trusted-policy-digest", pin, "--checks", "integrity", "--format", format, root)
					var out, diag bytes.Buffer
					cmd.Stdout = &out
					cmd.Stderr = &diag
					_ = cmd.Run()
					if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 3 || diag.Len() != 0 || out.Len() == 0 {
						t.Fatalf("actual bundle/context scan failed: %v %s %s", cmd.ProcessState, out.String(), diag.String())
					}
					if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String(), "sha256-") {
						t.Fatal("portable report leaked policy or ownership names")
					}
					if format == "terminal" {
						if !strings.Contains(out.String(), kind+"-context-claim") || !strings.Contains(out.String(), "modified") {
							t.Fatal("context/drift missing")
						}
						return
					}
					var r integrityscan.Report
					if format == "json" {
						if json.Unmarshal(out.Bytes(), &r) != nil {
							t.Fatal("report")
						}
					} else {
						var s struct {
							Runs []struct {
								Properties integrityscan.Report `json:"properties"`
							} `json:"runs"`
						}
						if json.Unmarshal(out.Bytes(), &s) != nil || len(s.Runs) != 1 {
							t.Fatal("SARIF")
						}
						r = s.Runs[0].Properties
					}
					mods := 0
					for _, d := range r.Comparison.Differences {
						if d.Kind == integrity.DifferenceModified {
							mods++
						}
					}
					if mods != 2 || r.Findings != 2 || len(r.Comparison.Gaps) != 0 {
						t.Fatalf("bundled drift suppressed or implicit dirs invented: %+v", r)
					}
					if !r.Comparison.SuppliedComparisonComplete {
						t.Fatal("complete explicit parent/bundle scope reported incomplete")
					}
					if r.NativeQualification != "not-run" || r.ExitCode != 3 {
						t.Fatal("scoped comparison promoted global qualification")
					}
					if len(r.Comparison.Contexts) != 1 {
						t.Fatal("context lost")
					}
				})
			}
		})
	}
}
