package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packtrace/internal/intel"
)

// The shared alias is inert metadata, never permission to merge originals/ranges.
func aliasAcceptanceSourceRecords() []archiveRecord {
	first := strings.ReplaceAll(matchingSourceRecords()[0].body, "MAL-2026-1", "MAL-2026-51")
	first = strings.Replace(first, `"modified":`, `"aliases":["GHSA-2345-6789-cfgh"],"modified":`, 1)
	second := strings.ReplaceAll(first, "MAL-2026-51", "MAL-2026-52")
	second = strings.Replace(second, `"source":"packtrace-fixture"`, `"source":"packtrace-fixture-secondary"`, 1)
	second = strings.Replace(second, `"versions":["1.0.0"]`, `"versions":["2.0.0"]`, 1)
	return []archiveRecord{{"MAL-2026-51.json", first, 0}, {"MAL-2026-52.json", second, 0}}
}

func TestAliasAcceptanceFixtureReproducible(t *testing.T) {
	data, id := matchingFixtureBundleFor(t, "matching-aliases", 2)
	t.Logf("generation=%x bytes=%d sha256=%x", id, len(data), sha256.Sum256(data))
	for _, record := range aliasAcceptanceSourceRecords() {
		t.Logf("original=%s sha256=%x", record.name, sha256.Sum256([]byte(record.body)))
	}
	if output := os.Getenv("PACKTRACE_ALIAS_FIXTURE_NEW_OUTPUT"); output != "" {
		f, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		n, we := f.Write(data)
		ce := f.Close()
		if we != nil || ce != nil || n != len(data) {
			t.Fatal(n, we, ce)
		}
		return
	}
	existing, e := os.ReadFile(filepath.Join("..", "execution", "testdata", "intel", "aliases.bundle"))
	if e != nil || !bytes.Equal(data, existing) {
		t.Fatal("nonreproducible alias fixture", e)
	}
	ctx := context.Background()
	input, _ := originalBundleInput(t, existing)
	defer input.Close()
	store, _ := transactionFixture(t)
	imported, e := store.Import(ctx, input, ImportOptions{})
	if e != nil || imported.Generation != id {
		t.Fatal("alias fixture import", e)
	}
	snapshot, e := store.ReadPinned(ctx, &id)
	if e != nil {
		t.Fatal(e)
	}
	defer snapshot.Close()
	evidence, _, e := snapshot.ReadIdentityLimited(ctx, "left-pad", 512<<20)
	if e != nil || len(evidence.Records) != 2 {
		t.Fatal("independent original bindings", e)
	}
	for _, authored := range aliasAcceptanceSourceRecords() {
		found := false
		for _, original := range evidence.Records {
			found = found || original.Header.ID.Value+".json" == authored.name && original.State == intel.SnapshotOriginalVerified && original.SHA256 == sha256.Sum256([]byte(authored.body)) && bytes.Equal(original.Raw, []byte(authored.body))
		}
		if !found {
			t.Fatal("alias changed an original's bound provenance/conditions", authored.name)
		}
	}
}
