package intelstore

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceMetadataUsesExactCanonicalFields(t *testing.T) {
	digest := md5.Sum([]byte("owned"))
	raw := fmt.Sprintf(`{"kind":"storage#object","bucket":"osv-vulnerabilities","name":"npm/all.zip","generation":"123","size":"5","md5Hash":%q,"updated":"2026-11-01T00:00:00Z","contentType":"application/zip","Generation":"456"}`, base64.StdEncoding.EncodeToString(digest[:]))
	meta, e := parseExportMetadata([]byte(raw))
	if e != nil || meta.Generation != "123" {
		t.Fatal("unknown case alias changed source authority", meta.Generation, e)
	}
}
func TestFullSyncSealFailureCannotPublishSourceDates(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	old := fixtureGeneration(t, s, "OLD-1", "2026-11-01T00:00:00Z")
	underlying, close := fullSourceFixture(t, "success")
	defer close()
	metaCalls := 0
	fetch := func(ctx context.Context, b *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
		ev, e := underlying(ctx, b, spec, out)
		if spec.kind == requestArchiveMeta {
			metaCalls++
			if metaCalls == 2 {
				raw := strings.ReplaceAll(ownedOSVRecord, "OWNED-1", "GHSA-2345-6789-cfgh")
				sum := sha256.Sum256([]byte(raw))
				ref := ObjectRef{sum, uint64(len(raw))}
				if e := os.WriteFile(filepath.Join(path, filepath.FromSlash(objectPath(ref))), bytes.Repeat([]byte{'x'}, len(raw)), 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
		return ev, e
	}
	if _, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch); e == nil {
		t.Fatal("corrupt original sealed as complete source")
	}
	got, _, e := s.readSelection(ctx)
	if e != nil || got.Current != fmt.Sprintf("%x", old) {
		t.Fatal("seal failure changed generation/source dates", e)
	}
}
