//go:build linux && (amd64 || arm64)

package integrityscan

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"packtrace/internal/integrity"
)

func TestPolicyPhysicalSeparation(t *testing.T) {
	for _, mode := range []string{"external", "hardlink", "ancestor-alias"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, _ := ownedFixture(t)
			switch mode {
			case "hardlink":
				if e := os.Link(policy, filepath.Join(target, "mutable-policy.json")); e != nil {
					t.Fatal(e)
				}
			case "ancestor-alias":
				config := filepath.Join(target, "config")
				if e := os.Mkdir(config, 0700); e != nil {
					t.Fatal(e)
				}
				b, e := os.ReadFile(policy)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(config, "policy.json"), b, 0600); e != nil {
					t.Fatal(e)
				}
				hop := filepath.Join(filepath.Dir(policy), "hop")
				if e = os.Symlink(target, hop); e != nil {
					t.Fatal(e)
				}
				policy = filepath.Join(hop, "config/policy.json")
			}
			read := watchContent(t, policy)
			_, e := AcquirePolicy(context.Background(), policy, target)
			if mode != "external" && read() {
				t.Fatal("rejected policy was content-read before separation")
			}
			if mode == "external" && e != nil {
				t.Fatal("external positive rejected", e)
			}
			if mode != "external" && e == nil {
				t.Fatal("target-backed controller policy admitted", mode)
			}
		})
	}
}

// IN_ACCESS observes content reads at the inode, not report redaction or opens.
// The fixture and inotify handle are owned; no permission/security changes.
func watchContent(t *testing.T, names ...string) func() bool {
	t.Helper()
	fd, e := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	for _, name := range names {
		if _, e = syscall.InotifyAddWatch(fd, name, syscall.IN_ACCESS); e != nil {
			t.Fatal(e)
		}
	}
	return func() bool {
		b := make([]byte, 4096)
		n, e := syscall.Read(fd, b)
		if e != nil && e != syscall.EAGAIN {
			t.Fatal(e)
		}
		return n > 0
	}
}

func TestAcquisitionDoesNotReadUnrelatedContent(t *testing.T) {
	for _, mode := range []string{"unrelated", "package-link", "package-hardlink", "unmapped-nested"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, p := ownedFixture(t)
			secret := filepath.Join(target, "unnecessary-secret")
			if e := os.WriteFile(secret, []byte("inert owned not-for-comparison canary"), 0600); e != nil {
				t.Fatal(e)
			}
			unused := filepath.Join(target, "unrelated-prepared.tgz")
			if e := os.WriteFile(unused, []byte("inert unrelated prepared bytes"), 0600); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "package-link":
				if e := os.Symlink("../../unnecessary-secret", filepath.Join(target, "node_modules/pkg/link")); e != nil {
					t.Fatal(e)
				}
			case "package-hardlink":
				if e := os.Link(secret, filepath.Join(target, "node_modules/pkg/hardlink")); e != nil {
					t.Fatal(e)
				}
			case "unmapped-nested":
				dir := filepath.Join(target, "node_modules/pkg/node_modules/unmapped")
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				secret = filepath.Join(dir, "secret")
				if e := os.WriteFile(secret, []byte("unselected physical owner"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			plan, hash := fixturePlan(t, policy, p)
			read := watchContent(t, secret, unused)
			var records []Record
			_, e := Acquire(context.Background(), target, filepath.Dir(policy), hash, plan, func(r Record) error { records = append(records, r); return nil })
			if e != nil || len(records) != 1 {
				t.Fatalf("positive in-scope scan refused: %v %+v", e, records)
			}
			if read() {
				t.Fatal("PURPOSE_BLOCKER: unrelated canary content read before filtering")
			}
			modified, added := false, false
			for _, d := range records[0].Assessment.Differences {
				modified = modified || d.Kind == integrity.DifferenceModified
				added = added || d.Kind == integrity.DifferenceAdded
			}
			// The existing owned fixture has both a real modification and an added file.
			if !modified || !added {
				t.Fatalf("in-scope drift lost: %+v", records)
			}
		})
	}
}

func TestReferencePhysicalSeparation(t *testing.T) {
	for _, mode := range []string{"hardlinked-archive", "ancestor-alias"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, p := ownedFixture(t)
			prepared := filepath.Dir(policy)
			if mode == "hardlinked-archive" {
				if e := os.Link(filepath.Join(prepared, "pkg.tgz"), filepath.Join(target, "archive.tgz")); e != nil {
					t.Fatal(e)
				}
			} else {
				b, e := os.ReadFile(filepath.Join(prepared, "pkg.tgz"))
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(target, "pkg.tgz"), b, 0600); e != nil {
					t.Fatal(e)
				}
				hop := filepath.Join(prepared, "hop")
				if e := os.Symlink(target, hop); e != nil {
					t.Fatal(e)
				}
				prepared = hop
			}
			plan, hash := fixturePlan(t, policy, p)
			read := watchContent(t, filepath.Join(prepared, "pkg.tgz"))
			var records []Record
			_, e := Acquire(context.Background(), target, prepared, hash, plan, func(r Record) error { records = append(records, r); return nil })
			if read() {
				t.Fatal("rejected reference content read before separation")
			}
			if e == nil && len(records) > 0 && len(records[0].Assessment.Differences) > 0 {
				t.Fatal("target-backed reference used for comparison")
			}
		})
	}
}
