package projectinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"packtrace/internal/nativefs"
)

func TestNPMLTSProducerReplay(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native fixture replay; not producer execution on this platform")
	}
	data, err := os.ReadFile("testdata/producer/npm-lts.json")
	sum := sha256.Sum256(data)
	if err != nil || hex.EncodeToString(sum[:]) != "5560e9f27738c6deb71fdbc27776fca42354448c306d91c4fade11b4dc35c9bc" {
		t.Fatal("captured producer evidence changed", err)
	}
	var docs []producerDocument
	if json.Unmarshal(data, &docs) != nil || len(docs) != 2 || docs[0].Profile != "npm@10.9.9" || docs[1].Profile != "npm@11.20.0" {
		t.Fatal("producer identities")
	}
	for _, doc := range docs {
		if doc.Format != 1 || !doc.Replay || len(doc.Captures) != 3 {
			t.Fatal("capture provenance")
		}
		for _, capture := range doc.Captures {
			for _, profile := range []string{"auto", doc.Profile} {
				t.Run(doc.Profile+"/"+capture.Case+"/"+profile, func(t *testing.T) {
					target := materializeProducer(t, capture)
					root, err := nativefs.OpenRoot(context.Background(), target)
					if err != nil {
						t.Fatal(err)
					}
					defer root.Close()
					got, err := Collect(context.Background(), root, Options{Profile: profile})
					counts := got.Model.Counts()
					if err != nil || !got.Complete || got.Selection.State != "usable" || counts.Locked == 0 || counts.Installed == 0 || counts.Scopes != capture.Expected.Scopes || ValidatePublic(Portable(got)) != nil {
						t.Fatalf("real npm output rejected: %+v counts=%+v gaps=%+v err=%v", got.Selection, counts, got.Model.Gaps, err)
					}
					for name, versions := range capture.Expected.Versions {
						for _, version := range versions {
							found := false
							for _, observation := range got.Model.Observations {
								found = found || observation.Class == "installed" && observation.Name == name && observation.Version == version
							}
							if !found {
								t.Fatal("installed version lost", name, version)
							}
						}
					}
				})
			}
		}
	}
}
