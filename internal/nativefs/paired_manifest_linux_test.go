//go:build linux

package nativefs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func pairedManifestFixture(t *testing.T) (*Root, *Root, string, string) {
	t.Helper()
	targetPath, cachePath := t.TempDir(), t.TempDir()
	name, peer := "node_modules/a/package.json", "a@1.0.0/package.json"
	for _, p := range []string{filepath.Join(targetPath, "node_modules/a"), filepath.Join(cachePath, "a@1.0.0")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	installed, cached := filepath.Join(targetPath, name), filepath.Join(cachePath, peer)
	if err := os.WriteFile(installed, []byte(`{"name":"a","version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(installed, cached); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(context.Background(), targetPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	cache, err := root.OpenExternalRoot(context.Background(), cachePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	return root, cache, installed, cached
}

func TestPairedManifestKeepsGenericRefusal(t *testing.T) {
	root, cache, _, _ := pairedManifestFixture(t)
	if f, err := root.OpenInput(context.Background(), "node_modules/a/package.json", 1024); err == nil {
		f.Close()
		t.Fatal("generic input admitted hardlink")
	}
	f, err := root.OpenPairedManifest(context.Background(), "node_modules/a/package.json", cache, "a@1.0.0/package.json", 1024)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil || string(data) != `{"name":"a","version":"1.0.0"}` || f.Stable() != nil || f.Close() != nil {
		t.Fatal("closed pair not read through original lease", err)
	}
}

func TestPairedManifestRejectsUnclosedOrChangedPairBeforeRead(t *testing.T) {
	for _, action := range []string{"third-before-open", "third-after-open", "transient-third", "replace-peer", "edit-content", "close-cache"} {
		t.Run(action, func(t *testing.T) {
			root, cache, installed, cached := pairedManifestFixture(t)
			third := filepath.Join(t.TempDir(), "unapproved-alias")
			if action == "third-before-open" {
				if err := os.Link(installed, third); err != nil {
					t.Fatal(err)
				}
				if f, err := root.OpenPairedManifest(context.Background(), "node_modules/a/package.json", cache, "a@1.0.0/package.json", 1024); err == nil {
					f.Close()
					t.Fatal("third alias admitted")
				}
				return
			}
			f, err := root.OpenPairedManifest(context.Background(), "node_modules/a/package.json", cache, "a@1.0.0/package.json", 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			switch action {
			case "third-after-open", "transient-third":
				if err := os.Link(installed, third); err != nil {
					t.Fatal(err)
				}
				if action == "transient-third" {
					if err := os.Remove(third); err != nil {
						t.Fatal(err)
					}
				}
			case "replace-peer":
				if err := os.Remove(cached); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cached, []byte(`{"name":"a","version":"1.0.0"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "edit-content":
				if err := os.WriteFile(cached, []byte(`{"name":"different"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "close-cache":
				cache.Close()
			}
			var b [1]byte
			if n, err := f.Read(b[:]); n != 0 || err == nil {
				t.Fatalf("changed pair exposed bytes: n=%d err=%v", n, err)
			}
		})
	}
}
