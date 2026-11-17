package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func scaleSourceRecords(count int, unroutable bool) []archiveRecord {
	records := fullMatchingSourceRecords(false)
	for i := len(records); i < count; i++ {
		id := fmt.Sprintf("MAL-2099-%06d", i)
		body := fmt.Sprintf(`{"id":%q,"modified":%q,"affected":[{"package":{"ecosystem":"npm","name":"scale-unselected-%06d"},"versions":["1.0.0"]}]}`, id, matchingFixtureDate, i)
		if unroutable && i == count-1 {
			body = strings.Replace(body, `"npm"`, `"PyPI"`, 1)
		}
		records = append(records, archiveRecord{id + ".json", body, 0})
	}
	return records
}

func TestConstructionScaleBundles(t *testing.T) {
	output := os.Getenv("PACKTRACE_SCALE_FIXTURES")
	if output == "" {
		t.Skip("explicit external fixture output required; no checked-in large corpus")
	}
	version := 2
	if os.Getenv("PACKTRACE_SCALE_LEGACY_RED") == "1" {
		version = 1
	}
	for _, tc := range []struct {
		count int
		bad   bool
	}{{1105, false}, {4105, false}, {4105, true}} {
		t.Run(fmt.Sprintf("%d-%t", tc.count, tc.bad), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fixed, _ := time.Parse(time.RFC3339, matchingFixtureDate)
				time.Sleep(fixed.Sub(time.Now()))
				store, _ := transactionFixture(t)
				fetch, close := fullSourceFixture(t, "matching-full", scaleSourceRecords(tc.count, tc.bad))
				defer close()
				result, err := store.syncFullVersion(context.Background(), &Budget{StagingBytes: 64 << 20}, fetch, version)
				if err != nil || result.Records != uint64(tc.count) {
					t.Fatal(result, err)
				}
				snapshot, err := store.ReadPinned(context.Background(), &result.Generation)
				if err != nil {
					t.Fatal(err)
				}
				defer snapshot.Close()
				used, err := snapshot.ValidateConstruction(context.Background(), 512<<20)
				if version == 2 && !tc.bad && err != nil {
					t.Fatal("proof", used, err)
				}
				if (version == 1 || tc.bad) && err == nil {
					t.Fatal("unearned proof")
				}
				var out bytes.Buffer
				if err := store.Export(context.Background(), snapshot, &out); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(out.Bytes(), []byte("original-index-validation.mac")) {
					t.Fatal("validation authority exported")
				}
				name := fmt.Sprintf("scale-%d-%t.bundle", tc.count, tc.bad)
				if err := os.WriteFile(filepath.Join(output, name), out.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				t.Logf("count=%d v=%d unroutable=%t generation=%x bundleBytes=%d proofRead=%d", tc.count, version, tc.bad, result.Generation, out.Len(), used)
			})
		})
	}
}

func TestConstructionStrictMetadata(t *testing.T) {
	for _, raw := range []string{`{"Version":3}`, `{"version":2,"Proof":{"Profile":"future"}}`} {
		if _, err := parsePreparation([]byte(raw)); err == nil {
			t.Fatal("unknown accepted", raw)
		}
	}
	p := newPreparation(2)
	raw, _ := json.Marshal(p)
	if _, err := parsePreparation(raw); err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"Profile":`), []byte(`"Extra":0,"Profile":`), 1)
	if _, err := parsePreparation(raw); err == nil {
		t.Fatal("unknown proof field")
	}
}
