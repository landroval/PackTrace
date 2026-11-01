//go:build darwin && cgo && (amd64 || arm64)

package nativefs

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Native-only contracts. Cross-builds do not execute or qualify these checks.
// Every path and special node below is an owned inert fixture; no devices.
func TestDarwinPreparedGuardRefusesOwnedFIFOOpen(t *testing.T) {
	p := t.TempDir()
	fifo := filepath.Join(p, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	regular := filepath.Join(p, "regular")
	if e := os.WriteFile(regular, []byte("owned"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := PrepareProcess(); e != nil {
		t.Fatalf("native preparation: %#v", e)
	}
	// Same owner/mode and same parent: policy must distinguish the selected
	// vnode type, not merely allow this directory or perform a post-open stat.
	fd, e := syscall.Open(regular, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal("ordinary positive control", e)
	}
	syscall.Close(fd)
	fd, e = syscall.Open(fifo, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if fd >= 0 {
		syscall.Close(fd)
	}
	if !errors.Is(e, syscall.EPERM) && !errors.Is(e, syscall.EACCES) {
		t.Fatal("owned special-node open was not denied by the prepared policy", e)
	}
}

func TestDarwinPreparedGuardRefusesOwnedUnixSocketOpen(t *testing.T) {
	// Relative binding avoids AF_UNIX's short address limit under CI roots;
	// testing.Chdir is confined to this nonparallel owned test process.
	t.Chdir(t.TempDir())
	listener, e := net.Listen("unix", "socket")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if e := PrepareProcess(); e != nil {
		t.Fatalf("native preparation: %#v", e)
	}
	fd, e := syscall.Open("socket", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if fd >= 0 {
		syscall.Close(fd)
	}
	if !errors.Is(e, syscall.EPERM) && !errors.Is(e, syscall.EACCES) && !errors.Is(e, syscall.ENXIO) && !errors.Is(e, syscall.EOPNOTSUPP) {
		t.Fatal("owned socket open was not safely refused", e)
	}
	t.Logf("owned socket refusal: %v", e)
}

func TestDarwinPreparedGuardTracksTheSelectedVnodeDuringRename(t *testing.T) {
	p := t.TempDir()
	slot, saved, fifo := filepath.Join(p, "slot"), filepath.Join(p, "saved"), filepath.Join(p, "fifo")
	if e := os.WriteFile(slot, []byte("owned"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if e := PrepareProcess(); e != nil {
		t.Fatalf("native preparation: %#v", e)
	}
	finished := make(chan error, 1)
	go func() {
		for i := 0; i < 64; i++ {
			for _, pair := range [][2]string{{slot, saved}, {fifo, slot}} {
				if e := syscall.Rename(pair[0], pair[1]); e != nil {
					finished <- e
					return
				}
			}
			runtime.Gosched()
			for _, pair := range [][2]string{{slot, fifo}, {saved, slot}} {
				if e := syscall.Rename(pair[0], pair[1]); e != nil {
					finished <- e
					return
				}
			}
		}
		finished <- nil
	}()
	var wrong error
	attempted, opened, denied := 0, 0, 0
	for i := 0; i < 256; i++ {
		attempted++
		fd, e := syscall.Open(slot, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if e != nil {
			if errors.Is(e, syscall.EPERM) || errors.Is(e, syscall.EACCES) {
				denied++
			}
			continue
		}
		opened++
		var s syscall.Stat_t
		e = syscall.Fstat(fd, &s)
		syscall.Close(fd)
		if e != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG {
			wrong = errors.New("selected special vnode was opened during rename")
			break
		}
		runtime.Gosched()
	}
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
	t.Logf("owned retarget: renameCycles=64 attempts=%d opened=%d policyDenied=%d otherRefusals=%d", attempted, opened, denied, attempted-opened-denied)
	if wrong != nil {
		t.Fatal(wrong)
	}
}

func darwinFixture(t *testing.T) (string, *Root) {
	t.Helper()
	p := t.TempDir()
	r, e := OpenRoot(t.Context(), p)
	if e != nil {
		t.Fatalf("native root: %#v", e)
	}
	t.Cleanup(func() { r.Close() })
	return p, r
}
func darwinRead(t *testing.T, r *Root, name, want string) {
	t.Helper()
	f, e := r.OpenRegular(t.Context(), name, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	b, e := io.ReadAll(f)
	if e != nil || string(b) != want {
		t.Fatal(string(b), e)
	}
	if e := f.Stable(); e != nil {
		t.Fatal(e)
	}
}
func TestDarwinSelectedAcquisitionAndNestedRegularFile(t *testing.T) {
	p, r := darwinFixture(t)
	if e := os.Mkdir(filepath.Join(p, "pkg"), 0700); e != nil {
		t.Fatal(e)
	}
	for n, s := range map[string]string{"pkg/file": "ok", "pkg/nested": "added", "secret": "not selected"} {
		if e := os.WriteFile(filepath.Join(p, n), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	darwinRead(t, r, "pkg/file", "ok")
	meta, e := r.Metadata(t.Context(), Limits{})
	if e != nil || !meta.Complete || meta.ReadBytes != 0 {
		t.Fatal(meta, e)
	}
	sub, e := r.OpenSubroot(t.Context(), "pkg")
	if e != nil {
		t.Fatal(e)
	}
	defer sub.Close()
	snap, e := sub.SnapshotPruned(t.Context(), Limits{}, func(e Entry) bool { return e.Name == "nested" && e.Kind == KindDirectory })
	if e != nil || !snap.Complete || snap.ReadBytes != 7 || len(snap.Entries) != 2 {
		t.Fatal(snap, e)
	}
	if f, e := r.OpenRegular(t.Context(), "pkg/file", 1); e == nil {
		f.Close()
		t.Fatal("size bound bypassed")
	}
	r.Close()
	if f, e := sub.OpenRegular(t.Context(), "file", 1024); e == nil {
		f.Close()
		t.Fatal("closed anchor admitted")
	}
}
func TestDarwinExternalIdentityHardlinksAndRelocation(t *testing.T) {
	p, target := darwinFixture(t)
	holder := t.TempDir()
	extPath := filepath.Join(holder, "controller")
	if e := os.Mkdir(extPath, 0700); e != nil {
		t.Fatal(e)
	}
	policy := filepath.Join(extPath, "policy")
	if e := os.WriteFile(policy, []byte("trusted"), 0600); e != nil {
		t.Fatal(e)
	}
	ext, e := target.OpenExternalRoot(t.Context(), extPath)
	if e != nil {
		t.Fatal(e)
	}
	defer ext.Close()
	f, e := ext.OpenInput(t.Context(), "policy", 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e := os.Link(policy, filepath.Join(p, "alias")); e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	if n, e := f.Read(b[:]); n != 0 || e == nil {
		t.Fatal("hardlink transition admitted", n, e)
	}
	if e := os.Remove(filepath.Join(p, "alias")); e != nil {
		t.Fatal(e)
	}
	// Capture fresh capabilities after the observable hardlink/directory churn.
	ext.Close()
	target.Close()
	target, e = OpenRoot(t.Context(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	ext, e = target.OpenExternalRoot(t.Context(), extPath)
	if e != nil {
		t.Fatal(e)
	}
	defer ext.Close()
	darwinRead(t, ext, "policy", "trusted")
	if e := os.Rename(holder, filepath.Join(p, "moved")); e != nil {
		t.Fatal(e)
	}
	if f, e := ext.OpenInput(t.Context(), "policy", 1024); e == nil {
		f.Close()
		t.Fatal("relocated external ancestor admitted")
	}
	for _, path := range []string{p, filepath.Dir(p)} {
		if other, e := target.OpenExternalRoot(t.Context(), path); e == nil {
			other.Close()
			t.Fatal("overlapping external root admitted")
		}
	}
}
func TestDarwinOriginalDescriptorNeverBecomesReplacementEvidence(t *testing.T) {
	p, r := darwinFixture(t)
	name := filepath.Join(p, "file")
	if e := os.WriteFile(name, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := r.OpenRegular(t.Context(), "file", 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e := os.Rename(name, filepath.Join(p, "retained")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(name, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	data, _ := io.ReadAll(f)
	if !strings.HasPrefix("original", string(data)) {
		t.Fatal("replacement bytes entered original capability", string(data))
	}
	if e := f.Stable(); e == nil {
		t.Fatal("changed root-relative identity became stable evidence")
	}
}

func TestDarwinLinksRemainContainedAndSpecialReadsRefused(t *testing.T) {
	p, r := darwinFixture(t)
	if e := os.WriteFile(filepath.Join(p, "file"), []byte("owned"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("file", filepath.Join(p, "inside")); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if e := os.WriteFile(outside, []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(p, "escape")); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Mkfifo(filepath.Join(p, "fifo"), 0600); e != nil {
		t.Fatal(e)
	}
	darwinRead(t, r, "inside", "owned")
	for _, name := range []string{"escape", "fifo", "../outside"} {
		if f, e := r.OpenRegular(context.Background(), name, 1024); e == nil {
			f.Close()
			t.Fatal("unsafe content admitted", name)
		}
	}
	if f, e := r.OpenInput(t.Context(), "inside", 1024); e == nil {
		f.Close()
		t.Fatal("input symlink admitted")
	}
}
