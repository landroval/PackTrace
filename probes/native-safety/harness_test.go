package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// CI integration worker: tests the real directory guard, not the native adapter.
// Invoked only by the controlled Python test wrapper in a proven-owned group.
func TestCILayoutWorker(t *testing.T) {
	if os.Getenv("PROBE_CI_LAYOUT_WORKER") != "1" {
		return
	}
	if len(os.Args) < 3 {
		t.Fatal("missing owned evidence argument")
	}
	f, err := openEvidence(os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatalf("CI layout rejected by real guard: %v", err)
	}
	f.Close()
	r := baseReceipt(actualEnvironment())
	r.Environment.Reason = "invalid-arguments"
	r.Status = "FAIL"
	if emit(os.Stdout, r) != nil {
		os.Exit(12)
	}
	os.Exit(2)
}

// Emit the actual complete Go schema for independent outer-validator tests.
func TestCIReceiptWorker(t *testing.T) {
	if os.Getenv("PROBE_CI_RECEIPT_WORKER") != "1" {
		return
	}
	if emit(os.Stdout, completeReceipt()) != nil {
		os.Exit(12)
	}
	os.Exit(0)
}

func TestCLIRejectsBeforeFixtures(t *testing.T) {
	for _, args := range [][]string{nil, {"--target", "anything"}, {"--evidence-dir"}, {"--observer", "forged"}, {"--evidence-dir", ""}} {
		var out bytes.Buffer
		if run(args, &out) != 2 {
			t.Fatalf("args admitted %q", args)
		}
		var r Receipt
		if json.Unmarshal(out.Bytes(), &r) != nil || r.Qualification != "not-qualified" || r.Binding != "not-established" || r.Status != "FAIL" {
			t.Fatalf("bad receipt %q", out.String())
		}
	}
	if !profileOK(actualEnvironment()) {
		dir := filepath.Join(t.TempDir(), "must-not-create")
		var out bytes.Buffer
		if run([]string{"--evidence-dir", dir}, &out) != 3 {
			t.Fatal("non-native run not blocked")
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatal("preflight created fixtures")
		}
	}
}
func TestTrustedMutationController(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "source")
	b := filepath.Join(dir, "spare")
	held := filepath.Join(dir, "held")
	os.WriteFile(a, []byte("owned-literal-A\n"), 0600)
	os.WriteFile(b, []byte("owned-literal-B\n"), 0600)
	fd, err := os.OpenFile(a, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	m := caseMutator{write: func(s string) error { _, err := fd.WriteAt([]byte(s), 0); return err }, swap: func(in bool) error {
		if in {
			if err := os.Rename(a, held); err != nil {
				return err
			}
			return os.Rename(b, a)
		}
		if err := os.Rename(a, b); err != nil {
			return err
		}
		return os.Rename(held, a)
	}}
	read := func(want string) {
		t.Helper()
		v, err := os.ReadFile(a)
		if err != nil || string(v) != want {
			t.Fatalf("mutation got %q %v want %q", v, err, want)
		}
	}
	for id := byte(1); id <= 5; id++ {
		if err := m.before(id); err != nil {
			t.Fatal(err)
		}
		if id == 5 {
			read("owned-literal-B\n")
		} else {
			read("owned-literal-A\n")
		}
		if err := m.after(id); err != nil {
			t.Fatal(err)
		}
		if id == 2 {
			read("owned-literal-B\n")
		} else {
			read("owned-literal-A\n")
		}
		if err := m.done(id); err != nil {
			t.Fatal(err)
		}
		read("owned-literal-A\n")
	}
	fd.Close()
	if m.after(2) == nil || m.done(2) == nil {
		t.Fatal("write error swallowed")
	}
	os.Remove(b)
	if m.before(5) == nil {
		t.Fatal("swap-in error swallowed")
	}
	if m.after(5) == nil {
		t.Fatal("restore error swallowed")
	}
}
func TestCleanupIdentity(t *testing.T) {
	expected := []Sample{{Device: 1, Inode: 10, Mode: 0100600, Nlink: 1}}
	for _, v := range []struct {
		s    Sample
		want bool
	}{
		{Sample{Device: 1, Inode: 10, Mode: 0100600, Nlink: 1, CtimeSec: 900}, true},
		{Sample{Device: 1, Inode: 11, Mode: 0100600, Nlink: 1}, false},
		{Sample{Device: 2, Inode: 10, Mode: 0100600, Nlink: 1}, false},
		{Sample{Device: 1, Inode: 10, Mode: 0040700, Nlink: 1}, false},
		{Sample{Device: 1, Inode: 10, Mode: 0100600, Nlink: 2}, false},
	} {
		if canUnlink(v.s, expected) != v.want {
			t.Errorf("unsafe cleanup decision %+v", v)
		}
	}
	if canUnlink(Sample{}, nil) {
		t.Fatal("unknown admitted")
	}
}
func TestEvidenceRoot(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	f, err := openEvidence(dir)
	if err != nil || f == nil {
		t.Fatalf("private empty root rejected %v", err)
	}
	f.Close()
	if err = os.WriteFile(filepath.Join(dir, "unknown"), []byte("leave"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err = openEvidence(dir); err == nil {
		if f != nil {
			f.Close()
		}
		t.Fatal("nonempty admitted")
	}
	b, err := os.ReadFile(filepath.Join(dir, "unknown"))
	if err != nil || string(b) != "leave" {
		t.Fatal("unknown artifact changed")
	}
	other := t.TempDir()
	os.Chmod(other, 0755)
	if _, err = openEvidence(other); err == nil {
		t.Fatal("public directory admitted")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(other, link)
	if _, err = openEvidence(link); err == nil {
		t.Fatal("symlink root admitted")
	}
	if _, err = openEvidence("."); err == nil {
		t.Fatal("relative root admitted")
	}
}

func TestEvidenceWorkingTreeExclusion(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(root, "evidence")
	source := filepath.Join(root, "source")
	for _, path := range []string{evidence, source} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(source)
	f, err := openEvidence(evidence)
	if err != nil {
		t.Fatalf("sibling evidence rejected: %v", err)
	}
	f.Close()
	t.Chdir(root)
	if f, err = openEvidence(evidence); err == nil || err.Error() != "output-under-working-tree" {
		if f != nil {
			f.Close()
		}
		t.Fatalf("descendant evidence guard relaxed: %v", err)
	}
}

// This worker implements the wire only; no native API result is inferred from it.
// Its ordering checks make premature mutation/inspection fail the controller.
func TestWireWorker(t *testing.T) {
	mode := os.Getenv("PROBE_WIRE_WORKER")
	if mode == "" {
		return
	}
	key := token{7}
	path := os.Getenv("PROBE_WIRE_MARKER")
	for id := byte(1); id <= 5; id++ {
		if _, err := readFrame(os.Stdin, key, opBegin, id); err != nil {
			os.Exit(11)
		}
		o := regularObservation()
		if id == 5 {
			o.AtClone.Inode = 12
			o.Digest = sha256.Sum256([]byte("owned-literal-B\n"))
		}
		if id == 3 {
			o = Observation{Errno: 62}
		}
		ready := o
		if mode == "badready" && id == 1 {
			ready.Before.Inode = 999
		}
		writeFrame(os.Stdout, key, frame{Op: opReady, ID: id, Observation: ready})
		if _, err := readFrame(os.Stdin, key, opClone, id); err != nil {
			os.Exit(12)
		}
		b, _ := os.ReadFile(path)
		if string(b) != "before"+strconv.Itoa(int(id)) {
			os.Exit(13)
		}
		writeFrame(os.Stdout, key, frame{Op: opCloned, ID: id, Observation: o})
		if _, err := readFrame(os.Stdin, key, opInspect, id); err != nil {
			os.Exit(14)
		}
		b, _ = os.ReadFile(path)
		if string(b) != "after"+strconv.Itoa(int(id)) {
			os.Exit(15)
		}
		if mode == "badresult" && id == 1 {
			o.Errno = 13
		}
		writeFrame(os.Stdout, key, frame{Op: opResult, ID: id, Observation: o})
	}
	if mode == "extra" {
		os.Stdout.Write([]byte("x"))
	}
	os.Exit(0)
}
func TestControllerWireAndFailures(t *testing.T) {
	for _, mode := range []string{"good", "badready", "badresult", "extra", "before-error", "after-error", "done-error"} {
		marker := filepath.Join(t.TempDir(), "marker")
		cmd := workerCommand("unused")
		cmd.Args = []string{os.Args[0], "-test.run=^TestWireWorker$"}
		cmd.Env = append(os.Environ(), "PROBE_WIRE_WORKER="+mode, "PROBE_WIRE_MARKER="+marker)
		receipt := baseReceipt(Environment{})
		count := 0
		hook := func(prefix string) func(byte) error {
			return func(id byte) error {
				if mode == prefix+"-error" {
					return errors.New("controlled failure")
				}
				return os.WriteFile(marker, []byte(prefix+strconv.Itoa(int(id))), 0600)
			}
		}
		r := childSession(cmd, func(r io.Reader, w io.Writer) error {
			return exchange(r, w, token{7}, &receipt, hook("before"), hook("after"), func(byte, Observation) error {
				count++
				if mode == "done-error" {
					return errors.New("controlled failure")
				}
				return nil
			})
		}, time.Second)
		if mode == "good" {
			if r.Err != nil || count != 5 || finish(&receipt, false) != 0 {
				t.Fatalf("good controller: %+v %+v count=%d", r, receipt, count)
			}
		} else if r.Err == nil {
			t.Fatalf("%s accepted", mode)
		}
		if !r.Reaped {
			t.Fatalf("%s unreaped", mode)
		}
	}
}
