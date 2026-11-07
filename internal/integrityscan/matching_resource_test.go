package integrityscan

import (
	"testing"

	"packtrace/internal/intel"
	"packtrace/internal/projectinventory"
)

func TestMatchingIdentityScopeRetainsReaderLimits(t *testing.T) {
	// The actual 4096/4097-binding reader control is
	// intel.TestReadSnapshotNPMIdentityLimits/bindings-4097. This boundary must retain
	// its successful partial-evidence resource label, not call it empty.
	complete := intel.SnapshotNPMEvidence{BlockState: intel.SnapshotStreamStructured, CatalogState: intel.SnapshotStreamStructured, Declaration: intel.SnapshotDeclarationVerified}
	for _, tc := range []struct {
		name     string
		evidence intel.SnapshotNPMEvidence
		want     string
	}{
		{"complete-empty-selection", complete, ""},
		{"binding-metadata-exhausted", intel.SnapshotNPMEvidence{BlockState: intel.SnapshotStreamStructured, Gaps: []intel.SnapshotGapKind{intel.SnapshotGapResource}}, "identity-resource-limit"},
		{"retained-original-exhausted", intel.SnapshotNPMEvidence{Records: []intel.SnapshotOriginalEvidence{{Problem: intel.SnapshotOriginalProblemResource}}}, "identity-resource-limit"},
		{"unverified-selection", intel.SnapshotNPMEvidence{}, "binding-unqualified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchingIdentityScopeGap(tc.evidence); got != tc.want {
				t.Fatalf("reader scope became false emptiness: %q != %q", got, tc.want)
			}
		})
	}
}

func TestMatchingEvaluationLimitCannotInventZeroWork(t *testing.T) {
	inventory := projectinventory.Portable(newMatchingFixture().inv)
	s := AdvisorySummary{TotalObservations: 1, Gaps: []string{"locked-only", "installed-unassessed", "declared-unassessed", "index-completeness", "evaluation-limit"}}
	if ValidateAdvisorySummary(s, []AdvisoryDecision{}, inventory) == nil {
		t.Fatal("zero-work closure hid every observation")
	}
}
