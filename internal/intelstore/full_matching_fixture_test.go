package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func fullFixtureGHSA(index int) string {
	const alphabet = "23456789cfghjmpqrvwx"
	part := []byte("2222")
	for i := len(part) - 1; i >= 0; i-- {
		part[i] = alphabet[index%len(alphabet)]
		index /= len(alphabet)
	}
	return "GHSA-" + string(part) + "-2345-6789"
}

// These are invented advisory claims, not downloaded records or executable packages.
func fullMatchingSourceRecords(corrected bool) []archiveRecord {
	modified := matchingFixtureDate
	if corrected {
		modified = "2026-10-03T00:00:00Z"
	}
	records := make([]archiveRecord, 0, 503)
	for i := range 503 {
		pkg := fmt.Sprintf("npmfixture-%04d", i%500)
		id, kind := fmt.Sprintf("MAL-2026-%d", i+1), "malicious"
		if i%2 != 0 {
			id, kind = fullFixtureGHSA(i), "vulnerability"
		}
		if i >= 500 {
			pkg = "npmfixture-0001"
			id, kind = fmt.Sprintf("MAL-2026-%d", 900000+i), "malicious"
		}
		versions := []string{"1.0.0"}
		if corrected && i%50 == 0 {
			versions = []string{"2.0.0"}
		}
		db := map[string]any{}
		source := fmt.Sprintf("https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/%s/%s.json", pkg, id)
		if kind == "malicious" {
			db["malicious-packages-origins"] = []any{map[string]any{"source": "packtrace-fixture", "sha256": strings.Repeat("a", 64), "import_time": modified, "modified_time": modified, "versions": versions}}
		} else {
			source = fmt.Sprintf("https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2026/10/%s/%s.json", id, id)
			db["github_reviewed"], db["severity"], db["cwe_ids"] = true, "HIGH", []string{"CWE-79"}
		}
		affected := map[string]any{"package": map[string]any{"ecosystem": "npm", "name": pkg}, "database_specific": map[string]any{"source": source}}
		if kind == "vulnerability" {
			fixed := "2.0.0"
			if corrected && i%50 == 1 {
				fixed = "1.0.0"
			}
			affected["ranges"] = []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": fixed}}}}
		} else {
			affected["versions"] = versions
			affected["database_specific"].(map[string]any)["cwes"] = []string{"CWE-506"}
		}
		record := map[string]any{"id": id, "modified": modified, "published": matchingFixtureDate, "affected": []any{affected}, "database_specific": db}
		if i == 500 || corrected && i%79 == 0 {
			record["withdrawn"] = modified
		}
		if i == 501 {
			db["withdrawn_versions"] = []string{"1.0.0"}
		}
		if i == 502 {
			affected["database_specific"].(map[string]any)["source"] = "https://unknown.invalid/source.json"
		}
		raw, e := json.Marshal(record)
		if e != nil {
			panic(e) // Authored fixed standard-library values only.
		}
		records = append(records, archiveRecord{id + ".json", string(raw), 0})
	}
	return records
}

func TestFullMatchingFixtureReproducible(t *testing.T) {
	for _, corrected := range []bool{false, true} {
		name, mode, date := "full.bundle", "matching-full", matchingFixtureDate
		if corrected {
			name, mode, date = "corrected.bundle", "matching-corrected", "2026-10-03T00:00:00Z"
		}
		t.Run(name, func(t *testing.T) {
			var data []byte
			synctest.Test(t, func(t *testing.T) {
				fixed, e := time.Parse(time.RFC3339, date)
				if e != nil {
					t.Fatal(e)
				}
				time.Sleep(fixed.Sub(time.Now()))
				store, _ := transactionFixture(t)
				fetch, close := fullSourceFixture(t, mode)
				defer close()
				result, e := store.syncFull(context.Background(), &Budget{StagingBytes: 64 << 20}, fetch)
				if e != nil || result.Records != 503 {
					t.Fatal("authored full source preparation", result, e)
				}
				snapshot, e := store.ReadPinned(context.Background(), &result.Generation)
				if e != nil {
					t.Fatal(e)
				}
				defer snapshot.Close()
				var out bytes.Buffer
				if e := store.Export(context.Background(), snapshot, &out); e != nil {
					t.Fatal(e)
				}
				data = out.Bytes()
				t.Logf("generation=%x", result.Generation)
			})
			t.Logf("fixture=%s bytes=%d sha256=%x", name, len(data), sha256.Sum256(data))
			if output := os.Getenv("PACKTRACE_FULL_FIXTURES_NEW_DIRECTORY"); output != "" {
				file, e := os.OpenFile(filepath.Join(output, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				n, writeErr := file.Write(data)
				closeErr := file.Close()
				if n != len(data) || writeErr != nil || closeErr != nil {
					t.Fatal("fixture output", n, writeErr, closeErr)
				}
				return
			}
			expected, e := os.ReadFile(filepath.Join("..", "execution", "testdata", "intel", name))
			if e != nil || !bytes.Equal(data, expected) {
				t.Fatal("authored fixture is not exactly reproducible", e)
			}
			if bytes.Contains(data, []byte("acquisition.key")) || bytes.Contains(data, []byte("local-acquisition.mac")) {
				t.Fatal("local acquisition authority was exported")
			}
		})
	}
}
