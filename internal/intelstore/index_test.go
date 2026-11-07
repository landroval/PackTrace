package intelstore

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestIndexMergesMoreThanThirtyTwoRunsInOrder(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	var runs []ObjectRef
	for i := 34; i >= 0; i-- {
		row := indexRow{V: 1, IdentityHash: strings.Repeat("2a", 32), Ecosystem: "npm", Name: "left-pad", SourceOrdinal: uint64(i), OriginalSHA256: strings.Repeat("01", 32), OriginalBytes: 1}
		raw, _ := json.Marshal(row)
		raw = append(raw, '\n')
		ref, e := tx.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
		if e != nil {
			t.Fatal(e)
		}
		runs = append(runs, ref)
	}
	ref, e := mergePartition(ctx, tx, runs)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.readRef(ctx, ref, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 35 {
		t.Fatal("merge dropped rows")
	}
	for i, line := range lines {
		var row indexRow
		if json.Unmarshal(line, &row) != nil || row.SourceOrdinal != uint64(i) {
			t.Fatal("external merge order", i)
		}
	}
}
func TestArchiveDeterministicOrdinalOrderAndCRCBounds(t *testing.T) {
	for _, mode := range []string{"ordered", "crc", "local-name", "descriptor-size", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Close()
			records := []archiveRecord{{"OWNED-2.json", strings.ReplaceAll(ownedOSVRecord, "OWNED-1", "OWNED-2"), 0}, {"OWNED-1.json", ownedOSVRecord, 0}}
			data := ownedArchive(t, records)
			if mode == "truncated" {
				data = data[:len(data)-10]
			}
			if mode == "local-name" {
				data[30] ^= 0x55
			}
			if mode == "descriptor-size" {
				z, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); if err != nil { t.Fatal(err) }
				offset, err := z.File[0].DataOffset(); if err != nil { t.Fatal(err) }
				data[offset+int64(z.File[0].CompressedSize64)+8] ^= 0x55
			}
			if mode == "crc" {
				z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				offset, err := z.File[0].DataOffset()
				if err != nil {
					t.Fatal(err)
				}
				data[offset] ^= 0x55
			}
			draft, e := prepareArchive(ctx, tx, bytes.NewReader(data), int64(len(data)))
			if mode != "ordered" {
				if e == nil {
					t.Fatal("invalid ZIP prepared")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			ids, e := s.readRef(ctx, tx.prep.record.SourceIDs, 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			lines := bytes.Split(bytes.TrimSpace(ids), []byte{'\n'})
			for i, line := range lines {
				var row sourceIDRow
				if json.Unmarshal(line, &row) != nil || row.ID != fmt.Sprintf("OWNED-%d", i+1) {
					t.Fatal("source ordinal order")
				}
			}
			if draft.Manifest.Bytes == 0 {
				t.Fatal("missing manifest")
			}
		})
	}
}
