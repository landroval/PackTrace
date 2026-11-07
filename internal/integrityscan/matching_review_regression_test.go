package integrityscan

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"packtrace/internal/intel"
	"packtrace/internal/projectinventory"
)

func TestLocalOversizedAdvisoryIDStaysOpaque(t *testing.T) {
	raw := strings.Replace(matchingRaw, "MAL-2026-1", "MAL-2026-"+strings.Repeat("1", 1<<20), 1)
	record := profileEvidence(t, []byte(raw))
	local := localAdvisoryRecord(record, 1)
	if local.ID != "" || ValidateLocalAdvisory(local) != nil {
		t.Fatal("oversized ID was not made opaque")
	}
	encoded, err := json.Marshal(local)
	if err != nil || len(encoded) > 1024 {
		t.Fatal("local frame not bounded", len(encoded), err)
	}
	local.ID = "MAL-2026-" + strings.Repeat("1", 256)
	if ValidateLocalAdvisory(local) == nil {
		t.Fatal("parent admitted oversized ID")
	}
}

func TestInstalledMetadataWitnessCannotUseOtherDirectory(t *testing.T) {
	snapshot, info := matchingSnapshot(t)
	fixture := matchingInstalledFixture()
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	var installed AdvisoryDecision
	_, err := MatchInventory(context.Background(), plan, fixture.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error {
		if d.Observation == 2 && d.EnforcementEligible {
			installed = d
		}
		return nil
	})
	public := projectinventory.PortableMatching(fixture.inv)
	if err != nil || installed.Observation != 2 || public.Observations[1].MetadataEvidence != 2 || ValidateAdvisoryDecision(plan, public, info, installed) != nil {
		t.Fatal("positive witness", err)
	}
	legacy := projectinventory.Portable(fixture.inv)
	if legacy.Observations[1].MetadataEvidence != 0 {
		t.Fatal("historical projection changed")
	}
	stripped := projectinventory.PortableMatching(fixture.inv)
	stripped.Observations[1].MetadataEvidence = 0
	if !reflect.DeepEqual(legacy, stripped) {
		t.Fatal("unexpected historical shape change")
	}
	public.Evidence[1].Status = "incomplete"
	public.Evidence = append(public.Evidence, projectinventory.PublicEvidence{ID: 4, Scope: 1, Method: "native-metadata-lease", Status: "complete"})
	public.Counts.Evidence++
	public.Complete = false
	if projectinventory.ValidatePublic(public) != nil {
		t.Fatal("forgery control must be otherwise valid")
	}
	if ValidateAdvisoryDecision(plan, public, info, installed) == nil {
		t.Fatal("unrelated complete directory rescued incomplete witness")
	}
	for _, id := range []uint32{0, 1, 3, 999} {
		fresh := projectinventory.PortableMatching(fixture.inv)
		fresh.Observations[1].MetadataEvidence = id
		if ValidateAdvisoryDecision(plan, fresh, info, installed) == nil {
			t.Fatal("invalid metadata reference", id)
		}
	}
}

func TestMatchingWorkExhaustionStopsSameWindowHydration(t *testing.T) {
	snapshot, info := matchingSnapshotNamed(t, "full.bundle")
	ctx := context.Background()
	byBucket := map[uint8]string{}
	var pair []string
	for i := 20; i < 500; i++ {
		name := fmt.Sprintf("npmfixture-%04d", i)
		bucket, err := intel.SnapshotNPMIdentityBlock(name)
		if err != nil {
			t.Fatal(err)
		}
		if previous := byBucket[bucket]; previous != "" {
			pair = []string{previous, name}
			break
		}
		byBucket[bucket] = name
	}
	names, _, err := intel.SnapshotNPMIdentityNames(pair)
	if err != nil || len(names) != 2 {
		t.Fatal("same-block fixture", err)
	}
	var records int
	firstBytes, err := snapshot.WalkIdentities(ctx, names[:1], maxMatchingBytes, func(_ string, e intel.SnapshotNPMEvidence) error { records = len(e.Records); return nil })
	if err != nil || records != 1 {
		t.Fatal("first original", records, err)
	}
	bothBytes, err := snapshot.WalkIdentities(ctx, names, maxMatchingBytes, func(_ string, e intel.SnapshotNPMEvidence) error {
		if len(e.Records) != 1 {
			t.Fatal("second original missing")
		}
		return nil
	})
	if err != nil || bothBytes <= firstBytes {
		t.Fatal("control must hydrate another actual original", firstBytes, bothBytes, err)
	}
	copies := make([]string, 2049)
	for i := range copies {
		copies[i] = names[0]
	}
	copies[len(copies)-1] = names[1]
	fixture := matchingScaleFixture(copies)
	plan := matchingPinnedPlan(t, info)
	plan.Policy.NPMOrigins = nil
	plan.Policy.NPMRegistry = "https://registry.npmjs.org"
	var rows []AdvisoryDecision
	summary, err := MatchInventory(ctx, plan, fixture.inv, snapshot, info, matchingNow, func(d AdvisoryDecision) error { rows = append(rows, d); return nil })
	if err != nil || summary.Work != 4096 || summary.BytesRead != firstBytes || !hasMatchingGap(summary.Gaps, "evaluation-limit") {
		t.Fatal("hydrated past work boundary", summary, firstBytes, bothBytes, err)
	}
	if ValidateAdvisorySummary(summary, rows, projectinventory.PortableMatching(fixture.inv)) != nil {
		t.Fatal("bounded partial closure")
	}
}
