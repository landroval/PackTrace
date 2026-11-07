package intelstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"packtrace/internal/intel"
	"testing"
)

func TestSealDerivesOriginalReachabilityFromCatalog(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	archive := ownedArchive(t, []archiveRecord{{"OWNED-1.json", ownedOSVRecord, 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil {
		t.Fatal(e)
	}
	original, e := intel.ParseOSVRecord([]byte(ownedOSVRecord))
	if e != nil {
		t.Fatal(e)
	}
	var metadata []ObjectRef
	for _, r := range draft.Objects {
		if r.SHA256 != original.SHA256 {
			metadata = append(metadata, r)
		}
	}
	draft.Objects = metadata
	id, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	descriptorRaw, e := s.readRef(ctx, tx.sealed[id].header.Descriptor, 4096)
	if e != nil {
		t.Fatal(e)
	}
	var d generationDescriptor
	if json.Unmarshal(descriptorRaw, &d) != nil {
		t.Fatal("descriptor")
	}
	graph, e := s.readRef(ctx, d.ObjectSet, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(graph, []byte(hex.EncodeToString(original.SHA256[:]))) {
		t.Fatal("seal omitted required original from reachability graph")
	}
}
