package integrity

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"
)

func TestAssessIntegrityRetainsValidSiblingAndRendersAllFormats(t *testing.T) {
	raw := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 3})
	b := archiveBinding(t, raw)
	claim := BindingInput{InstanceID: b.InstanceID(), Lockfile: BindingClaim{PackageID: "p", Version: "1", Origin: "o", ExpectedSRI: b.selectedToken, SourceLocator: "loc", SourceHash: b.selectedToken, EvidenceID: "e"}, SelectedBaseline: BaselineLockfile, SelectionReason: "selected", RequiredAssurance: AssuranceLockfile, Qualification: QualificationEvidence{ControllerEvidenceID: "q", Basis: "caller assertion"}}
	bad := claim
	bad.InstanceID = "bad"
	bad.Qualification = QualificationEvidence{}
	snapshot := InstalledSnapshot{Entries: []InstalledEntry{{EvidenceID: "observed", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Name: "a", Type: EntryFile, Size: 3, SHA256: [32]byte{}, Status: ObservationComplete}}, Scopes: []InstalledScope{{InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), EvidenceID: "scope", Enumerated: true, OwnershipKnown: true, Status: ObservationComplete}}}
	a, e := AssessIntegrity(context.Background(), []AssessmentRequest{{Binding: bad, Archive: bytes.NewReader(raw)}, {Binding: claim, Archive: bytes.NewReader(raw), Installed: snapshot}}, Limits{})
	if e != nil || a.NativeQualification != "not-run" || a.SuppliedComparisonComplete || len(a.Instances) != 2 || len(a.Instances[0].Gaps) == 0 || len(a.Instances[1].Differences) != 1 || a.Instances[1].Differences[0].Kind != DifferenceModified {
		t.Fatalf("sibling lost: %+v %v", a, e)
	}
	p := BuildPortableIntegrity(a)
	for _, f := range []string{"terminal", "json", "sarif"} {
		out, e := RenderIntegrity(p, f)
		if e != nil || !bytes.Contains(out, []byte("not-run")) || bytes.Contains(out, []byte(b.selectedToken)) {
			t.Fatalf("render %s %s %v", f, out, e)
		}
	}
}
func TestAssessIntegrityAccountsFailedReadsBeforeNextRequest(t *testing.T) {
	raw := archiveFixture(t, &tar.Header{Name: "package/a", Typeflag: tar.TypeReg, Size: 3})
	b := archiveBinding(t, raw)
	claim := BindingInput{InstanceID: b.InstanceID(), Lockfile: BindingClaim{PackageID: "p", Version: "1", Origin: "o", ExpectedSRI: b.selectedToken, SourceLocator: "loc", SourceHash: b.selectedToken, EvidenceID: "e"}, SelectedBaseline: BaselineLockfile, SelectionReason: "selected", RequiredAssurance: AssuranceLockfile, Qualification: QualificationEvidence{ControllerEvidenceID: "q", Basis: "caller assertion"}}
	other := claim
	other.InstanceID = "second"
	a, e := AssessIntegrity(context.Background(), []AssessmentRequest{{Binding: claim, Archive: bytes.NewReader(raw[:len(raw)-1])}, {Binding: other, Archive: bytes.NewReader(raw)}}, Limits{ReferenceReadBytes: int64(len(raw))})
	if e != nil || len(a.Instances) != 2 || len(a.Instances[0].Gaps) == 0 || len(a.Instances[1].Gaps) == 0 || len(a.Instances[1].Differences) != 0 {
		t.Fatalf("failure bytes reused: %+v %v", a, e)
	}
}
