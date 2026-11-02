package intelstore

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestKnownIDJoinDoesNotQueryUnrelatedEcosystemsAndRetainsPending(t *testing.T) {
	var old, changes bytes.Buffer
	ref := ObjectRef{SHA256: [32]byte{1}, Bytes: 1}
	for _, row := range []sourceIDRow{{ID: "GHSA-2345-6789-cfgh", Original: ref, Disposition: sourceUnresolved}, {ID: "MAL-2026-1", Original: ref}} {
		json.NewEncoder(&old).Encode(row)
	}
	for _, row := range []changeGroup{{ID: "MAL-2026-1", Modified: "2026-11-01T00:00:00Z", Empty: true}, {ID: "OTHER-1", Modified: "2026-11-01T00:00:00Z", Other: true}, {ID: "OTHER-2", Modified: "2026-11-01T00:00:00Z", NPM: true}} {
		json.NewEncoder(&changes).Encode(row)
	}
	var actions []updateAction
	if e := joinSourceChanges(context.Background(), &old, &changes, func(a updateAction) error { actions = append(actions, a); return nil }); e != nil {
		t.Fatal(e)
	}
	if len(actions) != 3 || actions[0].ID != "GHSA-2345-6789-cfgh" || !actions[0].Fetch || !actions[1].Fetch || actions[2].ID != "OTHER-2" || !actions[2].Fetch {
		t.Fatal("known-ID/source-only boundary lost", actions)
	}
}
