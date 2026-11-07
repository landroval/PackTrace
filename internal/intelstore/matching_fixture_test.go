package intelstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"packtrace/internal/intel"
)

const matchingFixtureDate = "2026-10-02T00:00:00Z"

// All source metadata below is authored/inert, not publisher authentication.
func matchingSourceRecords() []archiveRecord {
	const origins = `"malicious-packages-origins":[{"source":"packtrace-fixture","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","import_time":"2026-10-02T00:00:00Z","modified_time":"2026-10-02T00:00:00Z"}]`
	records := make([]archiveRecord, 0, 3)
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("MAL-2026-%d", i)
		withdrawal, correction := "", ""
		if i == 2 {
			withdrawal = `,"withdrawn":"2026-10-02T00:00:00Z"`
		}
		if i == 3 {
			correction = `,"withdrawn_versions":["1.0.0"]`
		}
		raw := fmt.Sprintf(`{"id":%q,"modified":"2026-10-02T00:00:00Z","published":"2026-10-02T00:00:00Z"%s,"affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}],"database_specific":{%s%s}}`, id, withdrawal, origins, correction)
		records = append(records, archiveRecord{id + ".json", raw, 0})
	}
	return records
}

type matchingFixtureTransport struct{ handler http.Handler }

func (tr matchingFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	out := httptest.NewRecorder()
	tr.handler.ServeHTTP(out, r)
	response := out.Result()
	response.Request = r
	return response, nil
}

// Generate via the actual full-source -> prepare -> seal -> export path under a
// fixed standard-library test clock. No descriptor/receipt/seal is fabricated.
func matchingFixtureBundle(t *testing.T) ([]byte, ID) {
	t.Helper()
	var data []byte
	var id ID
	synctest.Test(t, func(t *testing.T) {
		fixed, err := time.Parse(time.RFC3339, matchingFixtureDate)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(fixed.Sub(time.Now()))
		t.Logf("fixed clock: %s", time.Now().UTC())
		s, _ := transactionFixture(t)
		fetch, close := fullSourceFixture(t, "matching")
		defer close()
		traced := func(ctx context.Context, b *Budget, spec requestSpec, out io.Writer) (responseEvidence, error) {
			ev, err := fetch(ctx, b, spec, out)
			t.Logf("fixture request kind=%d evidence=%+v err=%v", spec.kind, ev, err)
			return ev, err
		}
		result, err := s.syncFull(context.Background(), &Budget{StagingBytes: 16 << 20}, traced)
		if err != nil {
			t.Fatal(err)
		}
		if result.Records != 3 {
			t.Fatal("missing authored records", result)
		}
		id = result.Generation
		snapshot, err := s.ReadPinned(context.Background(), &id)
		if err != nil {
			t.Fatal(err)
		}
		defer snapshot.Close()
		var out bytes.Buffer
		if err := s.Export(context.Background(), snapshot, &out); err != nil {
			t.Fatal(err)
		}
		data = out.Bytes()
	})
	return data, id
}

func TestMatchingFixtureReproducible(t *testing.T) {
	data, id := matchingFixtureBundle(t)
	t.Logf("generation=%x bytes=%d sha256=%x", id, len(data), sha256.Sum256(data))
	// Explicit opt-in only creates a NEW output. Even an explicit output cannot
	// overwrite an existing fixture (or another file).
	if output := os.Getenv("PACKTRACE_MATCHING_FIXTURE_NEW_OUTPUT"); output != "" {
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil || n != len(data) {
			t.Fatalf("fixture output: %d %v %v", n, writeErr, closeErr)
		}
		return
	}
	existing, err := os.ReadFile(filepath.Join("..", "execution", "testdata", "intel", "matching.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, existing) {
		t.Fatal("fixture differs from deterministic source pipeline output")
	}
	if bytes.Contains(data, []byte("acquisition.key")) || bytes.Contains(data, []byte("local-acquisition.mac")) {
		t.Fatal("private local source authority exported")
	}
	ctx := context.Background()
	input, _ := originalBundleInput(t, existing)
	store, _ := transactionFixture(t)
	result, err := store.Import(ctx, input, ImportOptions{})
	if err != nil || result.Generation != id {
		t.Fatal("actual fixture import", result, err)
	}
	snapshot, err := store.ReadPinned(ctx, &id)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	evidence, used, err := snapshot.ReadIdentityLimited(ctx, "left-pad", 512<<20)
	if err != nil || len(evidence.Records) != 3 || used != evidence.BytesRead {
		t.Fatal("fixture identity read", len(evidence.Records), used, err)
	}
	for _, authored := range matchingSourceRecords() {
		found := false
		for _, record := range evidence.Records {
			if bytes.Equal(record.Raw, []byte(authored.body)) && record.State == intel.SnapshotOriginalVerified {
				found = true
			}
		}
		if !found {
			t.Fatal("missing exact authored verified original", authored.name)
		}
	}
	now, _ := time.Parse(time.RFC3339, matchingFixtureDate)
	unqualified, err := snapshot.Observe(ctx, now, nil)
	if err != nil || unqualified.SourceAuthority != SourceUnqualified {
		t.Fatal("fixture import self-authorized", err)
	}
	designated, err := snapshot.Observe(ctx, now, &id)
	if err != nil || designated.SourceAuthority != SourceDesignated {
		t.Fatal("operator designation lost", err)
	}
}
