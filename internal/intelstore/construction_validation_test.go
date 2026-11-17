package intelstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConstructionValidationRoundtripAndBounds(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	prepared, err := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.ReadPinned(ctx, &prepared.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	used, err := snapshot.ValidateConstruction(ctx, 512<<20)
	if err != nil || used < 64 || used > 32<<10 {
		t.Fatal("construction/read charge", used, err)
	}
	failedBytes, err := snapshot.ValidateConstruction(ctx, used-1)
	if !errors.Is(err, ErrLimit) || failedBytes != used-1 {
		t.Fatal("failed proof read escaped budget", failedBytes, used, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := snapshot.ValidateConstruction(cancelled, used); err == nil {
		t.Fatal("cancelled proof admitted")
	}

	var archive bytes.Buffer
	if err := s.Export(ctx, snapshot, &archive); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive.Bytes(), []byte("original-index-validation.mac")) {
		t.Fatal("validation authority exported")
	}
	input, _ := originalBundleInput(t, archive.Bytes())
	other, path := transactionFixture(t)
	imported, err := other.Import(ctx, input, ImportOptions{})
	if err != nil || imported.Generation != prepared.Generation {
		t.Fatal("exact rebuild changed generation", imported, err)
	}
	if err := other.verifyLocal(ctx, imported.Generation); err == nil {
		t.Fatal("validation import gained acquisition authority")
	}
	pin, err := other.ReadPinned(ctx, &imported.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pin.ValidateConstruction(ctx, 512<<20); err != nil {
		t.Fatal("import did not rederive validation", err)
	}
	now := time.Now()
	unqualified, err := pin.Observe(ctx, now, nil)
	if err != nil || unqualified.SourceAuthority != SourceUnqualified {
		t.Fatal("import self-authorized", unqualified, err)
	}
	designated, err := pin.Observe(ctx, now, &imported.Generation)
	if err != nil || designated.SourceAuthority != SourceDesignated {
		t.Fatal("designation lost", designated, err)
	}
	source, err := snapshot.Observe(ctx, now, nil)
	if err != nil || designated.Check != source.Check || designated.FullReconciliation != source.FullReconciliation {
		t.Fatal("validation renewed age", designated, source, err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path, ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pin, err = reopened.ReadPinned(ctx, &imported.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if _, err := pin.ValidateConstruction(ctx, 512<<20); err != nil {
		t.Fatal("validation lost on read-only reopen", err)
	}
}

func TestConstructionValidationRejectsMissingAndCopiedAuthority(t *testing.T) {
	ctx := context.Background()
	s, path := transactionFixture(t)
	fetch, closeSource := fullSourceFixture(t, "success")
	defer closeSource()
	prepared, err := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.ReadPinned(ctx, &prepared.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	// These are public-sized MACs from owned temporary fixtures, never real keys.
	marker := filepath.Join(path, filepath.FromSlash(validationPath(prepared.Generation)))
	valid, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	acquisition, err := os.ReadFile(filepath.Join(filepath.Dir(marker), "local-acquisition.mac"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"missing", nil}, {"short", []byte{1}}, {"forged", bytes.Repeat([]byte{7}, 32)}, {"acquisition-domain", acquisition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.data == nil {
				err = os.Remove(marker)
			} else {
				err = os.WriteFile(marker, tc.data, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(marker, valid, 0600); err != nil {
					t.Error(err)
				}
			}()
			if _, err := snapshot.ValidateConstruction(ctx, 512<<20); err == nil {
				t.Fatal("invalid authority admitted")
			}
		})
	}
	var archive bytes.Buffer
	if err := s.Export(ctx, snapshot, &archive); err != nil {
		t.Fatal(err)
	}
	input, _ := originalBundleInput(t, archive.Bytes())
	other, otherPath := transactionFixture(t)
	if _, err := other.Import(ctx, input, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	otherMarker := filepath.Join(otherPath, filepath.FromSlash(validationPath(prepared.Generation)))
	if err := os.WriteFile(otherMarker, valid, 0600); err != nil {
		t.Fatal(err)
	}
	otherPin, err := other.ReadPinned(ctx, &prepared.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer otherPin.Close()
	if _, err := otherPin.ValidateConstruction(ctx, 512<<20); err == nil {
		t.Fatal("copied authority transferred stores")
	}

	// Key loss in an owned fixture must not trigger replacement or scan repair.
	key := filepath.Join(path, "acquisition.key")
	backup := filepath.Join(path, "owned-key-backup")
	if err := os.Rename(key, backup); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(backup, key); err != nil {
			t.Error(err)
		}
	}()
	if _, err := snapshot.ValidateConstruction(ctx, 512<<20); err == nil {
		t.Fatal("missing key admitted")
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatal("scan repaired key", err)
	}
}

func TestConstructionValidationRequiresBuilderCapability(t *testing.T) {
	ctx := context.Background()
	s, _ := transactionFixture(t)
	tx, err := s.begin(ctx, operationImport, &Budget{StagingBytes: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.attestValidation(ctx, ID{}); !errors.Is(err, ErrUntrusted) {
		t.Fatal("import flag alone granted validation", err)
	}
}
