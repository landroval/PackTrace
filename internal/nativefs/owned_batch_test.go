package nativefs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDurabilityFlushJoinsActualFileSyncFailure(t *testing.T) {
	good, e := os.CreateTemp(t.TempDir(), "good")
	if e != nil {
		t.Fatal(e)
	}
	defer good.Close()
	bad, e := os.CreateTemp(t.TempDir(), "closed")
	if e != nil {
		t.Fatal(e)
	}
	bad.Close()
	if e := batchSync(context.Background(), []*batchOriginal{{file: good}, {file: bad}}); e == nil {
		t.Fatal("failed original file flush became successful completion")
	}
}
func TestDurabilityBatchRequiresExactWriterAndFencesRetainedOriginal(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native durability")
	}
	ctx := context.Background()
	owner, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "owned"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	owner.WriteControl(ctx, "writer.lock", nil)
	owner.WriteControl(ctx, "other.lock", nil)
	wrong, e := owner.ReadRoot().TryOwnedLock(ctx, "other.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := owner.BeginDurabilityBatch(ctx, wrong); e == nil {
		b.Close()
		t.Fatal("wrong lock minted batch")
	}
	wrong.Close()
	writer, e := owner.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	batch, e := owner.BeginDurabilityBatch(ctx, writer)
	if e != nil {
		t.Fatal(e)
	}
	defer batch.Close()
	if e := batch.Mkdir(ctx, "stage"); e != nil {
		t.Fatal(e)
	}
	if e := batch.Mkdir(ctx, "objects"); e != nil {
		t.Fatal(e)
	}
	file, e := batch.CopyExclusive(ctx, "stage/item", bytes.NewReader([]byte("actual")), 6)
	if e != nil {
		t.Fatal(e)
	}
	if e := batch.Publish(ctx, file, "objects/item"); e != nil {
		t.Fatal(e)
	}
	file.Close()
	if e := batch.Fence(ctx); e != nil {
		t.Fatal("closed caller handle lost retained flush", e)
	}
}
func TestDurabilityBatchCancellationIsSticky(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	owner, e := OpenOwnedDirectory(ctx, filepath.Join(t.TempDir(), "owned"), true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	owner.WriteControl(ctx, "writer.lock", nil)
	writer, e := owner.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	b, e := owner.BeginDurabilityBatch(ctx, writer)
	if e != nil {
		t.Fatal(e)
	}
	f, e := b.CopyExclusive(ctx, "object", bytes.NewReader([]byte("data")), 4)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	cancel()
	if b.Fence(context.Background()) == nil || b.Fence(context.Background()) == nil || b.Close() == nil {
		t.Fatal("cancellation became durable completion")
	}
}
func TestDurabilityBatchChangedOriginalOrCancellationCannotFence(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native durability")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned")
	owner, e := OpenOwnedDirectory(ctx, path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	owner.WriteControl(ctx, "writer.lock", nil)
	writer, e := owner.ReadRoot().TryOwnedLock(ctx, "writer.lock", true)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	batch, e := owner.BeginDurabilityBatch(ctx, writer)
	if e != nil {
		t.Fatal(e)
	}
	defer batch.Close()
	file, e := batch.CopyExclusive(ctx, "item", bytes.NewReader([]byte("actual")), 6)
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	if e := writeOwnedFixture(filepath.Join(path, "item"), []byte("change")); e != nil {
		t.Fatal(e)
	}
	if e := batch.Fence(ctx); e == nil {
		t.Fatal("changed original issued durable fence")
	}
	if e := batch.Fence(ctx); e == nil {
		t.Fatal("failed fence renewed itself")
	}
}
