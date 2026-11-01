//go:build linux && (amd64 || arm64)

package integrityscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUnqualifiedBundleContentIsNotRead(t *testing.T) {
	for _, mode := range []string{"invalid-marker", "unpublished", "link-claim", "unknown-grandchild", "wrong-archive"} {
		t.Run(mode, func(t *testing.T) {
			root, policy, p := bundledFixture(t, true)
			location := "node_modules/pkg/" + ownedBundle
			canary := filepath.Join(root, filepath.FromSlash(location), "index.js")
			lockPath := filepath.Join(root, "package-lock.json")
			data, e := os.ReadFile(lockPath)
			if e != nil {
				t.Fatal(e)
			}
			var lock map[string]any
			if json.Unmarshal(data, &lock) != nil {
				t.Fatal("lock")
			}
			packages := lock["packages"].(map[string]any)
			switch mode {
			case "invalid-marker":
				packages[location].(map[string]any)["inBundle"] = "true"
			case "link-claim":
				packages[location].(map[string]any)["link"] = true
			case "unpublished", "unknown-grandchild":
				if mode == "unpublished" {
					location = "node_modules/pkg/node_modules/unpublished"
				} else {
					location += "/node_modules/unknown"
				}
				canary = filepath.Join(root, filepath.FromSlash(location), "secret")
				if os.MkdirAll(filepath.Dir(canary), 0700) != nil || os.WriteFile(canary, []byte("owned must-not-read"), 0600) != nil {
					t.Fatal("canary")
				}
				if mode == "unpublished" {
					packages[location] = map[string]any{"inBundle": true}
				}
			case "wrong-archive":
				if os.WriteFile(filepath.Join(filepath.Dir(policy), "pkg.tgz"), []byte("invalid owned archive"), 0600) != nil {
					t.Fatal("archive")
				}
			}
			data, _ = json.Marshal(lock)
			if os.WriteFile(lockPath, data, 0600) != nil {
				t.Fatal("owned lock")
			}
			read := watchContent(t, canary)
			records, _ := acquireOwned(t, root, policy, p)
			if read() {
				t.Fatal("PURPOSE_BLOCKER: bundle claim authorized unqualified content read", mode)
			}
			if records[0].Assessment.SuppliedComparisonComplete || len(records[0].Assessment.Gaps) == 0 {
				t.Fatal("unqualified scope completed", mode)
			}
		})
	}
}

func TestParentDoesNotReadSeparatelyMappedBundle(t *testing.T) {
	root, policy, p := mappedBundleFixture(t)
	plan, hash := fixturePlan(t, policy, p)
	read := watchContent(t, filepath.Join(root, "node_modules/pkg", filepath.FromSlash(ownedBundle), "index.js"))
	parent, child := false, false
	_, e := Acquire(context.Background(), root, filepath.Dir(policy), hash, plan, func(r Record) error {
		if r.Index == 0 {
			parent = true
			if read() {
				t.Fatal("parent read separately mapped child before pruning")
			}
		}
		if r.Index == 1 {
			child = true
			if !read() {
				t.Fatal("selected child content was not acquired by its own instance")
			}
		}
		return nil
	})
	if e != nil || !parent || !child {
		t.Fatal("missing owned phases", e)
	}
}

func TestQualifiedBundleReadsActualContent(t *testing.T) {
	root, policy, p := bundledFixture(t, true)
	read := watchContent(t, filepath.Join(root, "node_modules/pkg", filepath.FromSlash(ownedBundle), "index.js"))
	acquireOwned(t, root, policy, p)
	if !read() {
		t.Fatal("qualified published bundle was not actually read")
	}
}
