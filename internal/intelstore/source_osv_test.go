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
	archiveGeneration := "123"
	if strings.HasPrefix(mode, "replacement-") {
		id = "MAL-2026-2"
		record = strings.ReplaceAll(ownedOSVRecord, "OWNED-1", id)
		archiveGeneration = "124"
		if mode == "replacement-reused-generation" {
			archiveGeneration = "123"
		}
	}
	archive := ownedArchive(t, []archiveRecord{{id + ".json", record, 0}})
	digest := md5.Sum(archive)
	if mode == "checksum" {
		digest[0] ^= 0x55
	}
	metaCalls := 0
	csvDate, csvGeneration := "2026-11-01T00:00:00Z", "789"
	if strings.HasSuffix(mode, "-update") {
		csvDate, csvGeneration = "2026-11-01T01:00:00Z", "790"
	}
	if strings.HasPrefix(mode, "replacement-") {
		csvGeneration = "791"
	}
	if mode == "same-generation-update" {
		csvGeneration = "789"
	}
	csvBody := []byte(csvDate + ",npm/" + id + "\n")
	csvMD5 := md5.Sum(csvBody)
	client, close := ownedMappedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			if strings.HasPrefix(mode, "replacement-") && r.URL.Path == "/v1/vulns/GHSA-2345-6789-cfgh" {
				if mode == "replacement-unresolved" {
					w.WriteHeader(404)
					return
				}
				body := strings.ReplaceAll(ownedOSVRecord, "OWNED-1", "GHSA-2345-6789-cfgh")
				if mode == "replacement-withdrawn" {
					body = strings.Replace(body, `"affected":`, `"withdrawn":"2026-11-01T00:00:00Z","affected":`, 1)
				} else {
					body = strings.ReplaceAll(body, `"npm"`, `"PyPI"`)
				}
				io.WriteString(w, body)
				return
			}
			if r.URL.Path != "/v1/vulns/"+id {
				t.Error("non-source record lookup")
			}
			body := record
			if strings.HasSuffix(mode, "-update") {
				body = strings.ReplaceAll(body, "2026-11-01T00:00:00Z", csvDate)
			}
			if mode == "outside-update" {
				body = strings.ReplaceAll(body, `"npm"`, `"PyPI"`)
			}
			if mode == "wrong-id-update" {
				body = strings.ReplaceAll(body, id, "OTHER-1")
			}
			if mode == "unavailable-update" {
				w.WriteHeader(404)
				return
			}
			if mode == "retry-fail-update" {
				w.WriteHeader(503)
				io.WriteString(w, "owned failure")
				return
			}
			io.WriteString(w, body)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/storage/v1/") && strings.HasSuffix(r.URL.Path, "modified_id.csv") {
			json.NewEncoder(w).Encode(map[string]any{"kind": "storage#object", "bucket": "osv-vulnerabilities", "name": "modified_id.csv", "generation": csvGeneration, "size": fmt.Sprint(len(csvBody)), "contentType": "text/csv", "md5Hash": base64.StdEncoding.EncodeToString(csvMD5[:]), "updated": csvDate})
			return
		}
		if r.URL.Path == "/osv-vulnerabilities/modified_id.csv" {
			if r.URL.Query().Get("generation") != csvGeneration {
				t.Error("unbound CSV")
			}
			w.Header().Set("X-Goog-Generation", csvGeneration)
			w.Write(csvBody)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/storage/v1/") {
			metaCalls++
			generation := archiveGeneration
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
		if r.URL.Path != "/osv-vulnerabilities/npm/all.zip" || r.URL.Query().Get("generation") != archiveGeneration {
			t.Error("unbound media endpoint", r.URL.String())
			w.WriteHeader(400)
			return
		}
		generation := archiveGeneration
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
