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

func TestBun13ProducerReplay(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("native data replay, not producer execution on this platform")
	}
	data, err := os.ReadFile("testdata/producer/bun-1.3-lts.json")
	sum := sha256.Sum256(data)
	if err != nil || hex.EncodeToString(sum[:]) != "99277cd6792623fd26c3a58abec71b725663fa4b8a29b1307eb99239395af5e3" {
		t.Fatal("producer data changed", err)
	}
	var doc producerDocument
	if json.Unmarshal(data, &doc) != nil || doc.Profile != "bun@1.3.14" || !doc.Replay || len(doc.Captures) != 1 {
		t.Fatal("producer provenance")
	}
	for _, profile := range []string{"auto", "bun@1.3.x", "bun@1.3.14"} {
		t.Run(profile, func(t *testing.T) {
			dir := materializeProducer(t, doc.Captures[0])
			root, err := nativefs.OpenRoot(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			got, err := Collect(context.Background(), root, Options{Profile: profile})
			if err != nil || !got.Complete || got.Selection.Family != "bun" || got.Selection.State != "usable" || got.Model.Counts().Locked == 0 || got.Model.Counts().Installed == 0 || ValidatePublic(PortableMatching(got)) != nil {
				t.Fatal("real Bun output rejected", got, err)
			}
		})
	}
}
