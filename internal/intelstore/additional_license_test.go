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
			s, _ := transactionFixture(t)
			fetch, close := fullSourceFixture(t, mode)
			defer close()
			result, e := s.syncFull(ctx, &Budget{StagingBytes: 16 << 20}, fetch)
			if e != nil {
				t.Fatal("qualified additional source refused", e)
			}
			state, e := s.loadSourceState(ctx, result.Generation)
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
			pin, e := s.Pin(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer pin.Close()
			ob, e := s.Observe(ctx, pin, time.Now().UTC(), nil)
			if e != nil || ob.SourceAuthority != SourceLocal {
				t.Fatal("additional licenses lost local qualification", ob, e)
			}
			snapshot, e := s.ReadPinned(ctx, &result.Generation)
			if e != nil {
				t.Fatal(e)
			}
			defer snapshot.Close()
			var bundle bytes.Buffer
			if e := s.Export(ctx, snapshot, &bundle); e != nil {
				t.Fatal(e)
			}
			input, _ := originalBundleInput(t, bundle.Bytes())
			other, _ := transactionFixture(t)
			received, e := other.Import(ctx, input, ImportOptions{})
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
