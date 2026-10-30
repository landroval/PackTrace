package integrity

import (
	"encoding/base64"
	"strings"
	"testing"
)

func qualifiedBinding() BindingInput {
	d := "sha256-" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	c := BindingClaim{PackageID: "fixture", Version: "1", Origin: "fixture-origin", ExpectedSRI: d, SourceLocator: "fixture-lock", SourceHash: d, EvidenceID: "lock-1"}
	return BindingInput{InstanceID: "instance-1", Lockfile: c, SelectedBaseline: BaselineLockfile, SelectionReason: "lockfile reference", RequiredAssurance: AssuranceLockfile, Qualification: QualificationEvidence{ControllerEvidenceID: "controller-1", Basis: "caller-qualified synthetic fixture"}}
}

func TestResolveBindingRejectsUnqualifiedAndContradictoryClaims(t *testing.T) {
	in := qualifiedBinding()
	binding, gaps := ResolveReferenceBinding(in)
	if len(gaps) != 0 || !binding.Usable() || binding.InstanceID() != "instance-1" || binding.Algorithm() != "sha256" || len(binding.ExpectedDigests()) != 1 {
		t.Fatalf("valid supplied binding: %+v %+v", binding, gaps)
	}
	in.Qualification = QualificationEvidence{}
	binding, gaps = ResolveReferenceBinding(in)
	if binding.Usable() || len(gaps) == 0 {
		t.Fatal("unqualified fixture became usable")
	}
	in = qualifiedBinding()
	in.Controller = in.Lockfile
	in.Controller.ExpectedSRI = "sha256-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	in.SelectedBaseline = BaselineController
	in.RequiredAssurance = AssuranceIndependent
	binding, gaps = ResolveReferenceBinding(in)
	if binding.Usable() || len(gaps) == 0 {
		t.Fatal("contradictory digest became trusted")
	}
}

func TestResolveBindingRequiresCoherentProvenanceAndIndependentBaseline(t *testing.T) {
	in := qualifiedBinding()
	in.Lockfile.SourceHash = "not-a-digest"
	b, _ := ResolveReferenceBinding(in)
	if b.Usable() {
		t.Fatal("invalid source hash")
	}
	in = qualifiedBinding()
	in.SelectedBaseline = BaselineController
	in.RequiredAssurance = AssuranceIndependent
	b, _ = ResolveReferenceBinding(in)
	if b.Usable() {
		t.Fatal("missing controller claim")
	}
	in.Controller = in.Lockfile
	in.Controller.SourceLocator = "fixture-controller"
	in.Controller.EvidenceID = "controller-claim"
	b, g := ResolveReferenceBinding(in)
	if !b.Usable() || len(g) != 0 || b.Assurance() != AssuranceIndependent {
		t.Fatalf("independent fixture: %+v %+v", b, g)
	}
	in.Controller.PackageID = "other"
	b, _ = ResolveReferenceBinding(in)
	if b.Usable() {
		t.Fatal("conflicting identity")
	}
}

func TestResolveBindingRejectsContradictorySourceAssertions(t *testing.T) {
	in := qualifiedBinding()
	in.Controller = in.Lockfile
	in.Controller.EvidenceID = "controller-source"
	in.Controller.SourceHash = "sha256-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	b, g := ResolveReferenceBinding(in)
	if b.Usable() || len(g) == 0 {
		t.Fatal("same locator asserted with conflicting hashes")
	}
}

func TestBindingDigestCopiesAndStrongestSelection(t *testing.T) {
	in := qualifiedBinding()
	sha512Token := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))
	in.Lockfile.ExpectedSRI = sha512Token + " " + in.Lockfile.ExpectedSRI
	b, g := ResolveReferenceBinding(in)
	if !b.Usable() || len(g) != 0 || b.Algorithm() != "sha512" || b.selectedToken != sha512Token {
		t.Fatalf("strongest token not selected: %+v %+v", b, g)
	}
	digests := b.ExpectedDigests()
	digests[0][0] = 42
	if b.ExpectedDigests()[0][0] != 0 {
		t.Fatal("caller mutated binding digest")
	}
}

func TestLimitsBoundedNormalization(t *testing.T) {
	l, e := normalizedLimits(Limits{})
	if e != nil || l.CompressedBytes != 512<<20 || l.ExpandedBytes != 2<<30 || l.AggregateExpandedBytes != 8<<30 || l.Entries != 100000 || l.FileBytes != 256<<20 || l.ReferenceReadBytes != 16<<30 || l.TotalNameBytes != 16<<20 || l.NameBytes != 4096 || l.PathDepth != 128 {
		t.Fatalf("defaults: %+v %v", l, e)
	}
	l, e = normalizedLimits(Limits{CompressedBytes: 7, NameBytes: 4})
	if e != nil || l.CompressedBytes != 7 || l.NameBytes != 4 {
		t.Fatalf("smaller limits: %+v %v", l, e)
	}
	for _, bad := range []Limits{{CompressedBytes: (512 << 20) + 1}, {ExpandedBytes: (2 << 30) + 1}, {AggregateExpandedBytes: (8 << 30) + 1}, {Entries: 100001}, {FileBytes: (256 << 20) + 1}, {ReferenceReadBytes: (16 << 30) + 1}, {TotalNameBytes: (16 << 20) + 1}, {NameBytes: 4097}, {PathDepth: 129}, {Entries: -1}} {
		if _, e := normalizedLimits(bad); e == nil {
			t.Fatalf("accepted raised/negative limit: %+v", bad)
		}
	}
}
