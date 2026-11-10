package projectinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"packtrace/internal/managerprofile"
	"packtrace/internal/nativefs"
)

func TestExpandedManagerProducerReplay(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned native replay, not producer execution on this platform")
	}
	raw, e := os.ReadFile("testdata/producer/manager-ranges.json")
	sum := sha256.Sum256(raw)
	if e != nil || hex.EncodeToString(sum[:]) != "72942dd085bdc3cb2f4bb0373e427204f957329b19f94f7fb1e15b62ecbddb22" {
		t.Fatal("producer corpus changed", e)
	}
	var docs []producerDocument
	if json.Unmarshal(raw, &docs) != nil || len(docs) != 5 {
		t.Fatal("producer provenance")
	}
	expected := []string{"npm@7.24.2", "npm@8.19.4", "npm@9.9.4", "bun@1.2.23", "bun@1.4.2"}
	for i, doc := range docs {
		count := 4
		if doc.Profile == "bun@1.4.2" {
			count = 5
		}
		if doc.Profile != expected[i] || doc.Format != 1 || !doc.Replay || len(doc.Captures) != count {
			t.Fatal("producer identity/cases", doc.Profile)
		}
		profiles := []string{doc.Profile, "auto", managerprofile.NPMRange}
		if strings.HasPrefix(doc.Profile, "bun@") {
			profiles[2] = managerprofile.BunRange
			profiles = append(profiles, "bun@"+strings.Join(strings.Split(doc.Profile[4:], ".")[:2], ".")+".x")
		}
		for _, capture := range doc.Captures {
			for _, profile := range profiles {
				t.Run(doc.Profile+"/"+capture.Case+"/"+profile, func(t *testing.T) {
					target := materializeProducer(t, capture)
					root, e := nativefs.OpenRoot(context.Background(), target)
					if e != nil {
						t.Fatal(e)
					}
					defer root.Close()
					got, e := Collect(context.Background(), root, Options{Profile: profile})
					counts := got.Model.Counts()
					if e != nil || got.Selection.State != "usable" || counts.Locked == 0 || counts.Installed == 0 || counts.Scopes != capture.Expected.Scopes || ValidatePublic(PortableMatching(got)) != nil {
						t.Fatalf("actual producer rejected: selection=%+v counts=%+v gaps=%+v error=%v", got.Selection, counts, got.Model.Gaps, e)
					}
					if capture.Case == "hardlink" {
						if got.Complete || len(got.Model.Gaps) == 0 {
							t.Fatal("hardlink refusal laundered")
						}
						return
					}
					if capture.Case == "sources" {
						declared := map[string]bool{}
						for _, o := range got.Model.Observations {
							if o.Class == "declared" {
								declared[o.Name] = true
							}
						}
						for _, key := range capture.Expected.DeclaredKeys {
							if !declared[key] {
								t.Fatal("source declaration lost", key)
							}
						}
						return
					}
					if !got.Complete {
						t.Fatalf("supported producer slice incomplete: %+v", got.Model.Gaps)
					}
					versions := map[string]map[string]int{}
					for _, o := range got.Model.Observations {
						if o.Class == "installed" {
							if versions[o.Name] == nil {
								versions[o.Name] = map[string]int{}
							}
							versions[o.Name][o.Version]++
						}
					}
					for name, want := range capture.Expected.Versions {
						for _, version := range want {
							if versions[name][version] == 0 {
								t.Fatal("installed identity lost", name, version)
							}
						}
					}
					for _, name := range capture.Expected.OptionalAbsent {
						if len(versions[name]) > 0 {
							t.Fatal("optional absence invented as installation", name)
						}
					}
					if versions["fixture-common"]["1.0.0"] < capture.Expected.MinimumCommonOneCopies {
						t.Fatal("physical copies merged")
					}
					if capture.Case == "shrinkwrap" && got.Selection.File != "npm-shrinkwrap.json" {
						t.Fatal("shrinkwrap precedence changed")
					}
				})
			}
		}
	}
}
