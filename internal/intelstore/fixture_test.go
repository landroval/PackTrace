package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Later source/reader/CLI tests use the real owned ZIP→projection→index→seal
// pipeline. It proves storage preparation only, never actual OSV acquisition.
func fixtureGeneration(t *testing.T, s *Store, id, modified string) ID {
	t.Helper()
	ctx := context.Background()
	tx, e := s.begin(ctx, operationSync, &Budget{StagingBytes: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	closed := false
	defer func() {
		if !closed {
			tx.Close()
		}
	}()
	data, e := json.Marshal(map[string]any{"id": id, "modified": modified, "affected": []any{map[string]any{"package": map[string]any{"ecosystem": "npm", "name": "left-pad"}, "versions": []string{"1.0.0"}}}})
	if e != nil {
		t.Fatal(e)
	}
	archive := ownedArchive(t, []archiveRecord{{id + ".json", string(data), 0}})
	draft, e := prepareArchive(ctx, tx, bytes.NewReader(archive), int64(len(archive)))
	if e != nil {
		t.Fatal(e)
	}
	generation, e := tx.seal(ctx, draft)
	if e != nil {
		t.Fatal(e)
	}
	if e := tx.activate(ctx, generation); e != nil {
		t.Fatal(e)
	}
	if e := tx.Close(); e != nil {
		t.Fatal(e)
	}
	closed = true
	return generation
}
