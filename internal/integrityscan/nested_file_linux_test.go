//go:build linux && (amd64 || arm64)

package integrityscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"packtrace/internal/integrity"
)

// A package-shaped pathname is not a separate physical directory owner.
func TestOrdinaryAddedFileAtNestedSlot(t *testing.T) {
	for _, rel := range []string{"ordinary-extra", "node_modules/unmapped", "node_modules/@scope/unmapped"} {
		t.Run(rel, func(t *testing.T) {
			target, policy, p := ownedFixture(t)
			full := filepath.Join(target, "node_modules/pkg", rel)
			if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("inert ordinary added content"), 0600); err != nil {
				t.Fatal(err)
			}
			plan, hash := fixturePlan(t, policy, p)
			read := watchContent(t, full)
			var records []Record
			_, err := Acquire(context.Background(), target, filepath.Dir(policy), hash, plan, func(r Record) error {
				records = append(records, r)
				return nil
			})
			if err != nil || len(records) != 1 {
				t.Fatal(err, records)
			}
			if !read() {
				t.Fatal("ordinary selected-package file was not content-read")
			}
			added := 0
			for _, d := range records[0].Assessment.Differences {
				if d.Kind == integrity.DifferenceAdded {
					added++
				}
			}
			// One pre-existing added file, plus each new directory and file.
			want := 1 + len(strings.Split(rel, "/"))
			if added != want {
				t.Fatalf("added file suppressed: got=%d want=%d; assessment=%+v", added, want, records[0].Assessment)
			}
		})
	}
}
