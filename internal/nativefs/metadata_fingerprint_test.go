package nativefs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMetadataFingerprintBindsOriginalNotEqualBytes(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned metadata")
	}
	ctx := context.Background()
	var first [32]byte
	for i := 0; i < 2; i++ {
		path := filepath.Join(t.TempDir(), "owned")
		owner, e := OpenOwnedDirectory(ctx, path, true)
		if e != nil {
			t.Fatal(e)
		}
		defer owner.Close()
		f, e := owner.CopyExclusive(ctx, "item", bytes.NewReader([]byte("same")), 4)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
		lease, e := owner.ReadRoot().OpenMetadata(ctx, "item")
		if e != nil {
			t.Fatal(e)
		}
		defer lease.Close()
		fingerprint, e := lease.Fingerprint()
		if e != nil {
			t.Fatal(e)
		}
		ownedFingerprint, e := owner.RetirementFingerprint(ctx, lease)
		if e != nil || ownedFingerprint != fingerprint {
			t.Fatal("owned metadata fingerprint changed", e)
		}
		if i == 0 {
			first = fingerprint
		} else if first == fingerprint {
			t.Fatal("equal bytes laundered original identity")
		}
		if e := os.WriteFile(filepath.Join(path, "item"), []byte("changed"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := lease.Fingerprint(); e == nil {
			t.Fatal("changed retained object issued stable fingerprint")
		}
	}
}
