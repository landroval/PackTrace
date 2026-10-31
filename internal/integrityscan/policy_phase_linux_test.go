//go:build linux && (amd64 || arm64)

package integrityscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/cli"
)

func TestPolicyRevalidatedBeforeTargetContent(t *testing.T) {
	for _, mode := range []string{"hardlink-after-policy", "changed-policy"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, p := ownedFixture(t)
			observed, e := AcquirePolicy(context.Background(), policy, target)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := Configure(cli.ScanArgumentRequest{PolicyPath: policy, Checks: cli.ArgumentCheckIntegrity, Privacy: "portable", Output: "-", Manager: "auto"}, p)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "hardlink-after-policy" {
				if e = os.Link(policy, filepath.Join(target, "mutable-policy")); e != nil {
					t.Fatal(e)
				}
			} else {
				b, e := os.ReadFile(policy)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(policy, append(b, ' '), 0600); e != nil {
					t.Fatal(e)
				}
			}
			read := watchContent(t, filepath.Join(target, "node_modules/pkg/index.js"))
			emitted := false
			_, e = Acquire(context.Background(), target, filepath.Dir(policy), observed.SourceHash, plan, func(Record) error { emitted = true; return nil })
			if e == nil || emitted || read() {
				t.Fatalf("changed/target-backed policy controlled acquisition: %v emitted=%v", e, emitted)
			}
		})
	}
}
