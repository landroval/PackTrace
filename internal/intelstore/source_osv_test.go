package intelstore

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func fullSourceFixture(t *testing.T, mode string) (func(context.Context, *Budget, requestSpec, io.Writer) (responseEvidence, error), func()) {
	t.Helper()
	record := strings.ReplaceAll(ownedOSVRecord, "OWNED-1", "GHSA-2345-6789-cfgh")
	id := "GHSA-2345-6789-cfgh"
	if mode == "license" {
		record = ownedOSVRecord
		id = "OWNED-1"
	}
	if mode == "malicious" {
		id = "MAL-2026-1"
		record = strings.ReplaceAll(ownedOSVRecord, "OWNED-1", id)
	}
	archive := ownedArchive(t, []archiveRecord{{id + ".json", record, 0}})
	digest := md5.Sum(archive)
	if mode == "checksum" {
		digest[0] ^= 0x55
	}
	metaCalls := 0
	client, close := ownedMappedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/storage/v1/") {
			metaCalls++
			generation := "123"
			if mode == "changed" && metaCalls > 1 {
				generation = "456"
			}
			size := len(archive)
			if mode == "size" {
				size++
			}
			json.NewEncoder(w).Encode(map[string]any{"kind": "storage#object", "bucket": "osv-vulnerabilities", "name": "npm/all.zip", "generation": generation, "size": fmt.Sprint(size), "contentType": "application/zip", "md5Hash": base64.StdEncoding.EncodeToString(digest[:]), "updated": "2026-11-01T00:00:00Z"})
			return
		}
		if r.URL.Path != "/osv-vulnerabilities/npm/all.zip" || r.URL.Query().Get("generation") != "123" {
			t.Error("unbound media endpoint", r.URL.String())
			w.WriteHeader(400)
			return
		}
		generation := "123"
		if mode == "generation" {
			generation = "456"
		}
		w.Header().Set("X-Goog-Generation", generation)
		if mode == "partial" {
			w.Header().Set("Content-Length", fmt.Sprint(len(archive)+10))
			w.Write(archive[:len(archive)/2])
			return
		}
		w.Write(archive)
	}))
	return func(ctx context.Context, b *Budget, s requestSpec, out io.Writer) (responseEvidence, error) {
		return fetchUsing(ctx, b, s, out, client)
	}, close
}
func TestBootstrapActualPipelineSealsLocalSourceWithoutPublisherSignature(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, close := fullSourceFixture(t, "success")
	defer close()
	result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if e != nil {
		t.Fatal(e)
	}
	if result.Generation == (ID{}) || result.Records != 1 || result.Memberships != 1 {
		t.Fatal("incomplete bootstrap", result)
	}
	if e := s.verifyLocal(ctx, result.Generation); e != nil {
		t.Fatal("acquisition authority not retained", e)
	}
	selected, _, e := s.readSelection(ctx)
	if e != nil || selected.Current != fmt.Sprintf("%x", result.Generation) {
		t.Fatal("generation not actually activated", e)
	}
}
func TestFullSyncFailurePreservesOldGeneration(t *testing.T) {
	for _, mode := range []string{"generation", "changed", "size", "partial", "license", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, _ := transactionFixture(t)
			old := fixtureGeneration(t, s, "OLD-1", "2026-11-01T00:00:00Z")
			fetch, close := fullSourceFixture(t, mode)
			defer close()
			if _, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch); e == nil {
				t.Fatal("failed source activated")
			}
			selected, _, e := s.readSelection(ctx)
			if e != nil || selected.Current != fmt.Sprintf("%x", old) {
				t.Fatal("previous generation replaced", e)
			}
		})
	}
}
func TestFailedRevalidationKeepsOldTime(t *testing.T) {
	old := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if next := successfulCheckTime(old, old.Add(time.Hour), false); !next.Equal(old) {
		t.Fatal("failure renewed source check")
	}
	if next := successfulCheckTime(old, old.Add(-time.Hour), true); !next.Equal(old) {
		t.Fatal("clock rollback renewed source check")
	}
}
