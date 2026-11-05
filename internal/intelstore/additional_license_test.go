package intelstore

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestAdditionalPublisherLicensesSurviveSourceReaders(t *testing.T) {
	for _, mode := range []string{"eef", "gsd", "eef-with-github"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			started := time.Now()
			stage := func(name string) {
				now := time.Now()
				t.Logf("source-reader-stage=%s elapsed=%s", name, now.Sub(started))
				started = now
			}
			s, _ := transactionFixture(t)
			fetch, close := fullSourceFixture(t, mode)
			defer close()
			stage("fixture")
			result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
			stage("sync-full")
			if e != nil {
				t.Fatal("qualified additional source refused", e)
			}
			state, e := s.loadSourceState(ctx, result.Generation)
			stage("load-source-state")
			if e != nil {
				t.Fatal("incremental source state lost additional license", e)
			}
			want := 1
			if mode == "eef-with-github" {
				want = 2
			}
			if len(state.receipt.Attributions) != want || !licenseProfile(state.receipt, state.preparation) {
				t.Fatal("publisher counts/attributions lost")
			}
			for _, a := range state.receipt.Attributions {
				text, e := s.readRef(ctx, a.Text, 32<<10)
				if e != nil || len(text) == 0 {
					t.Fatal("full portable license missing", e)
				}
			}
			stage("license-texts")
			pin, e := s.Pin(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer pin.Close()
			ob, e := s.Observe(ctx, pin, time.Now().UTC(), nil)
			stage("local-observe")
			if e != nil || ob.SourceAuthority != SourceLocal {
				t.Fatal("additional licenses lost local qualification", ob, e)
			}
			snapshot, e := s.ReadPinned(ctx, &result.Generation)
			stage("read-pinned")
			if e != nil {
				t.Fatal(e)
			}
			defer snapshot.Close()
			var bundle bytes.Buffer
			if e := s.Export(ctx, snapshot, &bundle); e != nil {
				t.Fatal(e)
			}
			stage("export")
			input, _ := originalBundleInput(t, bundle.Bytes())
			other, _ := transactionFixture(t)
			received, e := other.Import(ctx, input, ImportOptions{})
			stage("import")
			if e != nil || received.Generation != result.Generation {
				t.Fatal("portable additional-profile semantic rebuild", received, e)
			}
			imported, e := other.ReadPinned(ctx, &received.Generation)
			if e != nil {
				t.Fatal(e)
			}
			defer imported.Close()
			unqualified, e := imported.Observe(ctx, time.Now(), nil)
			if e != nil || unqualified.SourceAuthority != SourceUnqualified {
				t.Fatal("transport imported local source authority", unqualified, e)
			}
			designated, e := imported.Observe(ctx, time.Now(), &result.Generation)
			if e != nil || designated.SourceAuthority != SourceDesignated {
				t.Fatal("independent designation lost licensed source", designated, e)
			}
			stage("imported-observations")
			for _, field := range []string{"publisher", "license", "origin"} {
				changed := state.receipt
				changed.Attributions = append([]sourceAttribution(nil), state.receipt.Attributions...)
				switch field {
				case "publisher":
					changed.Attributions[0].Publisher = "unqualified"
				case "license":
					changed.Attributions[0].License = "unqualified"
				case "origin":
					changed.Attributions[0].OriginURL = "https://example.invalid"
				}
				if licenseProfile(changed, state.preparation) {
					t.Fatalf("changed %s admitted", field)
				}
			}
		})
	}
}
