//go:build linux && (amd64 || arm64)

package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLegacyBootDeviceMarkerCannotBeAdoptedOrRewritten(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(path, "store.json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	var marker storeMarker
	if json.Unmarshal(raw, &marker) != nil {
		t.Fatal("fixture marker")
	}
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		t.Fatal("fixture stat")
	}
	var old [24]byte
	binary.LittleEndian.PutUint64(old[:8], uint64(st.Dev))
	binary.LittleEndian.PutUint64(old[8:16], st.Ino)
	binary.LittleEndian.PutUint64(old[16:], uint64(st.Uid))
	digest := sha256.Sum256(append([]byte("PackTrace:owned-root:linux:v2\x00"), old[:]...))
	marker.Root = hex.EncodeToString(digest[:])
	legacy, _ := json.Marshal(marker)
	if e := os.WriteFile(file, legacy, 0600); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []Mode{ReadOnly, CreateOwned} {
		opened, e := Open(ctx, path, mode)
		if opened != nil {
			opened.Close()
		}
		if !errors.Is(e, ErrBinding) {
			t.Fatal("legacy marker implicitly adopted", mode, e)
		}
		after, e := os.ReadFile(file)
		if e != nil || !bytes.Equal(after, legacy) {
			t.Fatal("failed admission rewrote the existing marker", mode, e)
		}
	}
}
