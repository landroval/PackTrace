package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestImportRebuildRejectsByteConsistentForgedIdentityIndex(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := s.ReadPinned(ctx, &result.Generation)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	evidence, e := snapshot.ReadIdentity(ctx, "left-pad")
	if e != nil || len(evidence.Records) != 1 {
		t.Fatal(e)
	}
	// Change only one binding in an actually prepared source graph; rehash every
	// touched object. This is a malicious derived index, not a digest typo.
	tx, e := s.begin(ctx, operationImport, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	hash := sha256.Sum256([]byte("npm\x00right-pad"))
	if hash[0] == 0x2a {
		t.Fatal("fixture hash prefix collision")
	}
	row := indexRow{1, hex.EncodeToString(hash[:]), "npm", "right-pad", 0, hex.EncodeToString(evidence.Records[0].SHA256[:]), evidence.Records[0].Bytes, 0}
	raw, _ := json.Marshal(row)
	raw = append(raw, '\n')
	badBlock, e := tx.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	manifestRaw, e := s.readRef(ctx, snapshot.descriptor.Manifest, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(manifestRaw, &fields) != nil {
		t.Fatal("manifest")
	}
	var blocks []map[string]any
	if json.Unmarshal(fields["blocks"], &blocks) != nil {
		t.Fatal("blocks")
	}
	empty := sha256.Sum256(nil)
	blocks[0x2a]["sha256"], blocks[0x2a]["bytes"], blocks[0x2a]["records"] = hex.EncodeToString(empty[:]), 0, 0
	blocks[hash[0]]["sha256"], blocks[hash[0]]["bytes"], blocks[hash[0]]["records"] = hex.EncodeToString(badBlock.SHA256[:]), badBlock.Bytes, 1
	fields["blocks"], _ = json.Marshal(blocks)
	manifestRaw, _ = json.Marshal(fields)
	badManifest, e := tx.put(ctx, bytes.NewReader(manifestRaw), uint64(len(manifestRaw)))
	if e != nil {
		t.Fatal(e)
	}
	set, e := s.openObjectSet(ctx, snapshot.descriptor.ObjectSet)
	if e != nil {
		t.Fatal(e)
	}
	var extras []ObjectRef
	for {
		ref, ok, e := set.next()
		if e != nil {
			t.Fatal(e)
		}
		if !ok {
			break
		}
		if !snapshot.catalog.Contains(ref.SHA256, ref.Bytes) {
			extras = append(extras, ref)
		}
	}
	set.Close()
	extras = append(extras, badBlock, badManifest)
	badID, e := tx.seal(ctx, generationDraft{Manifest: badManifest, Objects: extras, Cursor: snapshot.descriptor.Cursor, Provenance: snapshot.descriptor.Provenance})
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	forged, e := s.ReadPinned(ctx, &badID)
	if e != nil {
		t.Fatal(e)
	}
	defer forged.Close()
	var transport bytes.Buffer
	if e := s.Export(ctx, forged, &transport); e != nil {
		t.Fatal(e)
	}
	input, _ := originalBundleInput(t, transport.Bytes())
	other, _ := transactionFixture(t)
	old := fixtureGeneration(t, other, "OLD-1", "2026-11-01T00:00:00Z")
	if _, e := other.Import(ctx, input, ImportOptions{}); e == nil {
		t.Fatal("all hashes passed but derived binding forgery activated")
	}
	selected, _, e := other.readSelection(ctx)
	if e != nil || selected.Current != fmt.Sprintf("%x", old) {
		t.Fatal("failed rebuild replaced active generation", e)
	}
}
