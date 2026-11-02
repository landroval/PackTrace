package projectinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"packtrace/internal/nativefs"
)

type producerEntry struct {
	Path   string  `json:"path"`
	Kind   string  `json:"kind"`
	Data   *string `json:"data"`
	SHA256 string  `json:"sha256"`
	Target string  `json:"target"`
	Object int     `json:"object"`
	Links  int     `json:"links"`
}
type producerCapture struct {
	Case     string          `json:"case"`
	Layout   string          `json:"layout"`
	Backend  string          `json:"backend"`
	Entries  []producerEntry `json:"entries"`
	Expected struct {
		Versions               map[string][]string `json:"versions"`
		OptionalAbsent         []string            `json:"optionalAbsent"`
		MinimumCommonOneCopies int                 `json:"minimumCommonOneCopies"`
		Scopes                 int                 `json:"scopes"`
		DeclaredKeys           []string            `json:"declaredKeys"`
	} `json:"expected"`
}
type producerDocument struct {
	Format   int               `json:"format"`
	Profile  string            `json:"profile"`
	Replay   bool              `json:"replayIsNotProducerExecution"`
	Captures []producerCapture `json:"captures"`
}

// Reconstructs ONLY owned inert fixture data. It preserves original hardlink
// multiplicity (including aliases outside the selected fixture root) and raw
// link targets: a replay never copies an unsafe source into apparent safety.
func materializeProducer(t *testing.T, c producerCapture) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "project")
	if os.Mkdir(root, 0700) != nil {
		t.Fatal("fixture root")
	}
	entries := append([]producerEntry(nil), c.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	all := map[string]bool{}
	internal := map[int]int{}
	desired := map[int]int{}
	for _, e := range entries {
		if !cleanRelative(e.Path) || all[strings.ToLower(e.Path)] {
			t.Fatal("invalid/colliding recipe path")
		}
		all[strings.ToLower(e.Path)] = true
		if e.Kind == "file" {
			internal[e.Object]++
			if e.Links > desired[e.Object] {
				desired[e.Object] = e.Links
			}
		}
		if e.Kind == "directory" {
			if os.MkdirAll(filepath.Join(root, filepath.FromSlash(e.Path)), 0700) != nil {
				t.Fatal("fixture directory")
			}
		}
	}
	objects := map[int]string{}
	for _, e := range entries {
		if e.Kind != "file" {
			continue
		}
		name := filepath.Join(root, filepath.FromSlash(e.Path))
		if os.MkdirAll(filepath.Dir(name), 0700) != nil {
			t.Fatal("fixture parent")
		}
		if previous, ok := objects[e.Object]; ok {
			if os.Link(previous, name) != nil {
				t.Fatal("fixture internal hardlink")
			}
			continue
		}
		data := []byte("owned inert generic file; never read for inventory\n")
		if e.Data != nil {
			data = []byte(*e.Data)
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != e.SHA256 {
				t.Fatal("captured bytes changed")
			}
		}
		if os.WriteFile(name, data, 0600) != nil {
			t.Fatal("fixture file")
		}
		objects[e.Object] = name
	}
	for object, name := range objects {
		extra := desired[object] - internal[object]
		if extra < 0 || extra > 100000 {
			t.Fatal("recipe hardlink multiplicity")
		}
		for i := 0; i < extra; i++ {
			alias, err := os.CreateTemp(base, "owned-outside-alias-")
			if err != nil {
				t.Fatal(err)
			}
			path := alias.Name()
			if alias.Close() != nil || os.Remove(path) != nil || os.Link(name, path) != nil {
				t.Fatal("fixture external hardlink")
			}
		}
	}
	for _, e := range entries {
		if e.Kind != "link" {
			continue
		}
		if len(e.Target) > 4096 {
			t.Fatal("recipe link limit")
		}
		name := filepath.Join(root, filepath.FromSlash(e.Path))
		if os.MkdirAll(filepath.Dir(name), 0700) != nil {
			t.Fatal("fixture link parent")
		}
		if err := os.Symlink(filepath.FromSlash(e.Target), name); err != nil {
			if runtime.GOOS == "windows" {
				t.Skip("Windows link creation unavailable: this producer/layout replay is NOT qualified")
			}
			t.Fatal("owned recipe symlink", err)
		}
	}
	return root
}
func TestPinnedProducerInventoryReplay(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("inventory native profile excludes deferred platforms")
	}
	indexBytes, e := os.ReadFile("testdata/producer/index.json")
	if e != nil {
		t.Fatal(e)
	}
	var index struct {
		Producers []struct {
			File, Profile, SHA256 string
			Bytes                 int
		} `json:"producers"`
	}
	if json.Unmarshal(indexBytes, &index) != nil || len(index.Producers) != 5 {
		t.Fatal("producer corpus index")
	}
	for _, row := range index.Producers {
		t.Run(row.Profile, func(t *testing.T) {
			data, e := os.ReadFile(filepath.Join("testdata/producer", row.File))
			if e != nil || len(data) != row.Bytes {
				t.Fatal("source corpus missing")
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != row.SHA256 {
				t.Fatal("source corpus hash")
			}
			var doc producerDocument
			if json.Unmarshal(data, &doc) != nil || doc.Format != 1 || doc.Profile != row.Profile || !doc.Replay || len(doc.Captures) == 0 {
				t.Fatal("producer source identity")
			}
			for _, c := range doc.Captures {
				t.Run(c.Case, func(t *testing.T) {
					root := materializeProducer(t, c)
					r, e := nativefs.OpenRoot(context.Background(), root)
					if e != nil {
						t.Fatal(e)
					}
					defer r.Close()
					got, e := Collect(context.Background(), r, Options{Profile: doc.Profile})
					if e != nil {
						t.Fatal(e)
					}
					if got.Selection.State != "usable" || got.Model.Counts().Locked == 0 || got.Model.Counts().Installed == 0 {
						t.Fatalf("real producer evidence not inventoried: %s %s %+v counts=%+v gaps=%+v", doc.Profile, c.Case, got.Selection, got.Model.Counts(), got.Model.Gaps)
					}
					if ValidatePublic(Portable(got)) != nil {
						t.Fatal("real producer public closure rejected")
					}
					if got.Model.Counts().Scopes != c.Expected.Scopes {
						t.Fatal("workspace scope mismatch", got.Model.Counts())
					}
					if c.Case == "hardlink" {
						if got.Complete || len(got.Model.Gaps) == 0 {
							t.Fatal("hardlinked manifests silently copied into qualified evidence")
						}
						return
					}
					if c.Case == "sources" {
						declared := map[string]bool{}
						for _, o := range got.Model.Observations {
							if o.Class == "declared" {
								declared[o.Name] = true
							}
						}
						for _, name := range c.Expected.DeclaredKeys {
							if !declared[name] {
								t.Fatal("nonregistry declaration erased", name)
							}
						}
						return
					}
					if !got.Complete {
						t.Fatalf("supported actual producer/layout incomplete: %s %s %+v", doc.Profile, c.Case, got.Model.Gaps)
					}
					versions := map[string]map[string]int{}
					for _, o := range got.Model.Observations {
						if o.Class != "installed" {
							continue
						}
						if versions[o.Name] == nil {
							versions[o.Name] = map[string]int{}
						}
						versions[o.Name][o.Version]++
					}
					for name, want := range c.Expected.Versions {
						for _, v := range want {
							if versions[name][v] == 0 {
								t.Fatal("physical version/copy missing", name, v, versions)
							}
						}
					}
					for _, name := range c.Expected.OptionalAbsent {
						if len(versions[name]) != 0 {
							t.Fatal("optional lock claim manufactured installation", name)
						}
					}
					if versions["fixture-common"]["1.0.0"] < c.Expected.MinimumCommonOneCopies {
						t.Fatal("same identity copies merged", versions)
					}
					if c.Case == "shrinkwrap" && got.Selection.File != "npm-shrinkwrap.json" {
						t.Fatal("actual shrinkwrap precedence lost", got.Selection)
					}
				})
			}
		})
	}
}
