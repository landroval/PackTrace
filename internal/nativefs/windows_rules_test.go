package nativefs

import (
	"encoding/binary"
	"testing"
)

// These run the production Windows input boundary on Linux, not the NT kernel.
// Removing the namespace or reparse bounds checks must fail these controls.
func TestWindowsOpenOptionsKeepRecallGuardOutsideTrustedAnchor(t *testing.T) {
	const root = `\Device\HarddiskVolume3\`
	base := uint32(winSynchronous | winOpenReparse | winNoRecall)
	for _, tc := range []struct {
		parent       bool
		name         string
		wanted, want uint32
		valid        bool
	}{
		{false, root, winDirectory, winDirectory | winSynchronous | winOpenReparse, true},
		{true, "", winDirectory, base, true},
		{true, "package.json", 0, base, true},
		{true, "", winNonDirectory, base | winNonDirectory, true},
		{true, "pkg", winDirectory, 0, false},
		{false, `C:\owned\`, winDirectory, 0, false},
		{false, root + `..`, winDirectory, 0, false},
		{false, root + `\`, winDirectory, 0, false},
		{false, `\Device\HarddiskVolume\`, winDirectory, 0, false},
		{false, root, 0, 0, false},
		{true, "", winDirectory | winNonDirectory, 0, false},
		{true, "", 0xffffffff, 0, false},
	} {
		got, e := winOpenOptions(tc.parent, tc.name, tc.wanted)
		if (e == nil) != tc.valid || tc.valid && got != tc.want {
			t.Fatalf("parent=%t name=%q wanted=%08x got=%08x error=%v", tc.parent, tc.name, tc.wanted, got, e)
		}
	}
}

func TestWindowsComponentBoundary(t *testing.T) {
	for _, n := range []string{"package.json", "node_modules", "@scope", "a-b_1", "A.txt"} {
		if winComponent(n) != nil {
			t.Fatalf("ordinary component rejected: %q", n)
		}
	}
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, "a:b", "NUL", "nul.txt", "COM1", "Lpt9.ext", "CONIN$", "CON .txt", "COM1 .txt", "PROGRA~1", "x.", "x ", "a?", "a*", "é", "a\x00b"} {
		if winComponent(n) == nil {
			t.Fatalf("namespace ambiguity admitted: %q", n)
		}
	}
}
func TestWindowsAbsoluteBoundary(t *testing.T) {
	for _, n := range []string{`\\.\NUL`, `\\?\C:\a`, `\??\C:\a`, `C:a`, `C:\a\..\b`, `C:\a:stream`, `\\server\share`, `C:\a\`, `C:\a.`, `C:\NUL`} {
		if _, _, e := winRootPath(n); e == nil {
			t.Fatalf("unsafe root admitted: %q", n)
		}
	}
	drive, parts, e := winRootPath(`c:\owned\target`)
	if e != nil || drive != "C:" || len(parts) != 2 || parts[1] != "target" {
		t.Fatal(drive, parts, e)
	}
}
func TestWindowsRelativeLinkBoundary(t *testing.T) {
	if p, e := winLinkPath([]string{"a"}, "../b", []string{"file"}); e != nil || p != "b/file" {
		t.Fatal(p, e)
	}
	for _, target := range []string{"../../escape", `C:\escape`, `\??\NUL`, "b:stream", "/escape", "../NUL"} {
		if _, e := winLinkPath([]string{"a"}, target, nil); e == nil {
			t.Fatalf("escape admitted: %q", target)
		}
	}
}

// This tests the production identity decision, not descriptor acquisition or
// live NTFS ancestry. Names/hashes cannot make overlapping identities disjoint.
func TestWindowsVolumeReplyBoundary(t *testing.T) {
	// MS-FSA 2.1.5.13.4: the underlying device type is DISK (7), not
	// DISK_FILE_SYSTEM (8). A filesystem name alone cannot admit a provider.
	device := []byte{7, 0, 0, 0, 0, 0, 0, 0}
	attr := []byte{0, 0, 0, 0, 255, 0, 0, 0, 8, 0, 0, 0, 'N', 0, 'T', 0, 'F', 0, 'S', 0}
	if e := winVolumeReply(device, attr); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func([]byte, []byte){
		func(d, a []byte) { d[0] = 8 }, func(d, a []byte) { d[4] = 16 },
		func(d, a []byte) { a[12] = 'R' }, func(d, a []byte) { a[8] = 255 }, func(d, a []byte) { a[4] = 254 },
	} {
		d, a := append([]byte(nil), device...), append([]byte(nil), attr...)
		mutate(d, a)
		if winVolumeReply(d, a) == nil {
			t.Fatal("unsupported volume admitted")
		}
	}
	for i := 0; i < len(attr); i++ {
		if winVolumeReply(device, attr[:i]) == nil {
			t.Fatal("truncated volume reply admitted")
		}
	}
}

func TestWindowsPhysicalChainDecision(t *testing.T) {
	mk := func(ids ...uint64) []stamp {
		var out []stamp
		for _, id := range ids {
			out = append(out, stamp{dev: 9, ino: id, mode: 0040000})
		}
		return out
	}
	for _, c := range []struct {
		a, b []stamp
		want int
		ok   bool
	}{
		{mk(1, 2, 3), mk(1, 2, 4), 1, true},
		{mk(1, 2, 3), mk(1, 5, 4), 0, true},
		{mk(1, 2), mk(1, 2), 0, false},
		{mk(1, 2), mk(1, 2, 3), 0, false},
		{mk(1, 2, 3), mk(1, 2), 0, false},
		{mk(1, 2), mk(7, 8), 0, false},
		{nil, mk(1), 0, false},
	} {
		got, e := winDisjointChains(c.a, c.b)
		if (e == nil) != c.ok || (c.ok && got != c.want) {
			t.Fatal(c, got, e)
		}
	}
	a, b := mk(1, 2), mk(1, 3)
	b[0].dev = 10
	if _, e := winDisjointChains(a, b); e == nil {
		t.Fatal("volume serial mismatch admitted")
	}
}

func TestWindowsReparseBufferBounds(t *testing.T) {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa000000c)
	binary.LittleEndian.PutUint16(b[4:], 16)
	binary.LittleEndian.PutUint16(b[10:], 4)
	binary.LittleEndian.PutUint32(b[16:], 1)
	b[20] = 'o'
	b[22] = 'k'
	if s, e := winReparseTarget(b); e != nil || s != "ok" {
		t.Fatal(s, e)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 3 }, func(b []byte) { b[4] = 255 }, func(b []byte) { b[8] = 255 },
		func(b []byte) { b[10] = 3 }, func(b []byte) { b[16] = 0 }, func(b []byte) { b[21] = 1 },
	} {
		c := append([]byte(nil), b...)
		mutate(c)
		if _, e := winReparseTarget(c); e == nil {
			t.Fatal("malformed reparse accepted")
		}
	}
	for i := 0; i < len(b); i++ {
		if _, e := winReparseTarget(b[:i]); e == nil {
			t.Fatal("truncation accepted", i)
		}
	}
}
