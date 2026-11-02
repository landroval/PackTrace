package intelstore

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

func TestChangeCaptureBindsMetadataGenerationAndActualBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Close()
	body := []byte("2026-11-01T00:00:00Z,npm/MAL-2026-1\n")
	digest := md5.Sum(body)
	fetch := func(ctx context.Context, b *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
		if spec.kind == requestChangesMeta {
			raw, _ := json.Marshal(map[string]any{"kind": "storage#object", "bucket": "osv-vulnerabilities", "name": "modified_id.csv", "generation": "123", "size": fmt.Sprint(len(body)), "md5Hash": base64.StdEncoding.EncodeToString(digest[:]), "updated": "2026-11-01T00:00:00Z", "contentType": "text/csv"})
			out.Write(raw)
			return responseEvidence{status: 200, bytes: uint64(len(raw))}, nil
		}
		if spec.kind != requestChanges || spec.generation != "123" {
			t.Fatal("unbound CSV destination")
		}
		out.Write(body)
		return responseEvidence{status: 200, bytes: uint64(len(body)), generation: "123"}, nil
	}
	meta, _, e := readSourceMetadata(tx.work, tx, requestChanges, fetch)
	if e != nil {
		t.Fatal(e)
	}
	original, _, e := captureSourceBody(tx.work, tx, requestChanges, meta, fetch)
	if e != nil {
		t.Fatal(e)
	}
	defer original.Close()
	got := make([]byte, len(body))
	if _, e := original.ReadAt(got, 0); e != nil || string(got) != string(body) {
		t.Fatal("retained source CSV lost", e)
	}
}
