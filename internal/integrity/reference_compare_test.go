package integrity

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func compareFixture() (ReferenceBinding, ReferenceCatalog, InstalledSnapshot) {
	in := qualifiedBinding()
	in.InstanceID = "private-instance"
	b, _ := ResolveReferenceBinding(in)
	d := sha256.Sum256([]byte("original"))
	c := ReferenceCatalog{instanceID: b.InstanceID(), bindingFingerprint: b.fingerprint, verified: true, entries: []ReferenceEntry{{EntryID: "ref-a", Name: "a", Type: EntryFile, Size: 8, SHA256: d}, {EntryID: "ref-b", Name: "b", Type: EntryFile, Size: 8, SHA256: d}}}
	s := InstalledSnapshot{Entries: []InstalledEntry{{EvidenceID: "obs-a", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Name: "a", Type: EntryFile, Size: 7, SHA256: sha256.Sum256([]byte("changed")), Status: ObservationComplete}}, Scopes: []InstalledScope{{EvidenceID: "scope-1", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Enumerated: true, OwnershipKnown: true, Status: ObservationComplete}}}
	return b, c, s
}

func TestComparePreservesModifiedAndCoveredMissing(t *testing.T) {
	b, c, s := compareFixture()
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) != 0 || !a.SuppliedComparisonComplete || len(a.Differences) != 2 || a.Differences[0].Kind != DifferenceModified || a.Differences[0].EvidenceID != "obs-a" || a.Differences[1].Kind != DifferenceMissing || a.Differences[1].EvidenceID != "scope-1" {
		t.Fatalf("compare: %+v %v", a, e)
	}
}
func TestCompareObservedMatchesWithoutEnumerationCannotClaimCoverage(t *testing.T) {
	b, c, s := compareFixture()
	s.Scopes = nil
	s.Entries = append(s.Entries, InstalledEntry{EvidenceID: "obs-b", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Name: "b", Type: EntryFile, Size: 8, SHA256: c.entries[1].SHA256, Status: ObservationComplete})
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || a.SuppliedComparisonComplete || len(a.Gaps) == 0 || len(a.Differences) != 2 {
		t.Fatalf("unbounded additions hidden: %+v %v", a, e)
	}
}
func TestCompareUnreadableDoesNotBecomeAbsent(t *testing.T) {
	b, c, s := compareFixture()
	s.Entries[0].Status = ObservationUnreadable
	s.Scopes[0].Enumerated = false
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || a.SuppliedComparisonComplete || len(a.Gaps) == 0 {
		t.Fatalf("gap required: %+v %v", a, e)
	}
	for _, d := range a.Differences {
		if d.Kind == DifferenceMissing {
			t.Fatal("unknown became missing")
		}
	}
}
func TestCompareRejectsUnverifiedCatalogAndAmbiguousOwnership(t *testing.T) {
	b, c, s := compareFixture()
	c.verified = false
	if _, e := CompareReferenceCatalog(b, c, s); e == nil {
		t.Fatal("unverified catalog compared")
	}
	c.verified = true
	s.Entries[0].OwnerInstanceID = "nested"
	s.Entries = append(s.Entries, InstalledEntry{EvidenceID: "nested-extra", InstanceID: b.InstanceID(), OwnerInstanceID: "nested", Name: "extra", Type: EntryFile, Status: ObservationComplete})
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) == 0 {
		t.Fatalf("ownership not flagged: %+v %v", a, e)
	}
	for _, d := range a.Differences {
		if d.Kind == DifferenceAdded || d.Kind == DifferenceModified {
			t.Fatalf("nested owner compared: %+v", d)
		}
	}
}
func TestCompareTypeAndContextRemainVisible(t *testing.T) {
	b, c, s := compareFixture()
	s.Entries[0].Type = EntryLink
	s.Entries[0].LinkTarget = "private-target"
	s.Scopes[0].Context = ContextPatch
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Differences) == 0 || a.Differences[0].Kind != DifferenceTypeChanged {
		t.Fatalf("type drift suppressed: %+v %v", a, e)
	}
	s.Entries = append(s.Entries, InstalledEntry{EvidenceID: "extra", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Name: "generated", Type: EntryFile, Status: ObservationComplete})
	a, e = CompareReferenceCatalog(b, c, s)
	if e != nil || a.Differences[len(a.Differences)-1].Kind != DifferenceAdded {
		t.Fatalf("context suppressed added: %+v %v", a, e)
	}
}
func TestCompareExplicitPackageRootDoesNotCreateFalseGap(t *testing.T) {
	b, c, s := compareFixture()
	c.entries = append([]ReferenceEntry{{EntryID: "root", Name: "", Type: EntryDirectory}}, c.entries...)
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) != 0 || !a.SuppliedComparisonComplete {
		t.Fatalf("archive root became a gap: %+v %v", a, e)
	}
}
func TestCompareUnqualifiedScopeCannotProveMissing(t *testing.T) {
	b, c, s := compareFixture()
	s.Scopes[0].Prefix = "../"
	s.Entries = nil
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) == 0 {
		t.Fatalf("unqualified scope: %+v %v", a, e)
	}
	for _, d := range a.Differences {
		if d.Kind == DifferenceMissing {
			t.Fatal("invalid scope proves absence")
		}
	}
}
func TestCompareAddedLinkRemainsUnsupportedGap(t *testing.T) {
	b, c, s := compareFixture()
	s.Entries = append(s.Entries, InstalledEntry{EvidenceID: "symlink", InstanceID: b.InstanceID(), OwnerInstanceID: b.InstanceID(), Name: "new-link", Type: EntryLink, LinkTarget: "private", Status: ObservationComplete})
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) == 0 {
		t.Fatalf("link scope not flagged: %+v %v", a, e)
	}
	for _, d := range a.Differences {
		if d.Kind == DifferenceAdded {
			t.Fatalf("link represented as qualified addition: %+v", d)
		}
	}
}
func closureInput(raw []byte) BindingInput {
	in := qualifiedBinding()
	d := sha256.Sum256(raw)
	in.Lockfile.ExpectedSRI = "sha256-" + base64.StdEncoding.EncodeToString(d[:])
	in.Lockfile.SourceHash = in.Lockfile.ExpectedSRI
	return in
}

func closureFixture(t *testing.T, names ...string) (ReferenceBinding, ReferenceCatalog, InstalledSnapshot, []byte) {
	t.Helper()
	var headers []*tar.Header
	for _, name := range names {
		h := &tar.Header{Name: "package/" + name, Typeflag: tar.TypeReg, Size: 3}
		if name == "" || strings.HasSuffix(name, "/") {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		headers = append(headers, h)
	}
	raw := archiveFixture(t, headers...)
	in := closureInput(raw)
	b, gaps := ResolveReferenceBinding(in)
	c, err := InspectReferenceArchive(context.Background(), b, bytes.NewReader(raw), Limits{})
	if err != nil || len(gaps) != 0 {
		t.Fatalf("fixture: %v %v", err, gaps)
	}
	s := InstalledSnapshot{Scopes: []InstalledScope{{InstanceID: in.InstanceID, OwnerInstanceID: in.InstanceID, EvidenceID: "root", Enumerated: true, OwnershipKnown: true, Status: ObservationComplete}}}
	for _, name := range names {
		if name != "" && !strings.HasSuffix(name, "/") {
			s.Entries = append(s.Entries, InstalledEntry{Name: name, EvidenceID: name, InstanceID: in.InstanceID, OwnerInstanceID: in.InstanceID, Type: EntryFile, Size: 3, SHA256: sha256.Sum256([]byte("xxx")), Status: ObservationComplete})
		}
	}
	return b, c, s, raw
}

func TestClosureSuppliedContracts(t *testing.T) {
	t.Run("positive-envelope-and-real-package", func(t *testing.T) {
		b, c, s, _ := closureFixture(t, "", "a", "package", "node_modules/local")
		a, err := CompareReferenceCatalog(b, c, s)
		if err != nil || !a.SuppliedComparisonComplete || len(a.Differences) != 3 {
			t.Fatalf("envelope/real package: %+v %v", a, err)
		}
		for _, d := range a.Differences {
			if d.Kind != DifferenceUnchanged {
				t.Fatalf("false drift: %+v", a)
			}
		}
	})
	t.Run("exact-binding-and-json-seal", func(t *testing.T) {
		b, c, s, raw := closureFixture(t, "a")
		beforeB, beforeC := b, c
		for _, target := range []any{&b, &c} {
			if err := json.Unmarshal([]byte(`{"InstanceID":"forged","Assurance":2}`), target); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(beforeB, b) || !reflect.DeepEqual(beforeC, c) {
			t.Error("JSON mutated qualification")
		}
		for _, mutate := range []func(*BindingInput){
			func(i *BindingInput) { i.Lockfile.PackageID += "x" },
			func(i *BindingInput) { i.Lockfile.Version += "x" },
			func(i *BindingInput) { i.Lockfile.Origin += "x" },
			func(i *BindingInput) { i.Lockfile.SourceLocator += "x" },
			func(i *BindingInput) { i.Lockfile.SourceHash = qualifiedBinding().Lockfile.SourceHash },
			func(i *BindingInput) { i.Lockfile.EvidenceID += "x" },
			func(i *BindingInput) { i.SelectionReason += "x" },
			func(i *BindingInput) { i.Qualification.Basis += "x" },
			func(i *BindingInput) { i.Qualification.ControllerEvidenceID += "x" },
			func(i *BindingInput) {
				i.Controller = i.Lockfile
				i.Controller.SourceLocator += "x"
				i.Controller.EvidenceID += "x"
				i.RequiredAssurance = AssuranceIndependent
				i.SelectedBaseline = BaselineController
			},
			func(i *BindingInput) { i.Lockfile.ExpectedSRI = qualifiedBinding().Lockfile.ExpectedSRI },
		} {
			in := closureInput(raw)
			mutate(&in)
			other, gaps := ResolveReferenceBinding(in)
			if len(gaps) != 0 {
				t.Fatal("invalid mutation fixture", gaps)
			}
			if a, err := CompareReferenceCatalog(other, beforeC, s); err == nil && len(a.Differences) != 0 {
				t.Error("cross-binding comparison accepted")
			}
		}
	})
	t.Run("all-scopes-before-differences", func(t *testing.T) {
		for _, status := range []ObservationStatus{ObservationUnreadable, ObservationExcluded, ObservationUnstable, ObservationComplete} {
			for _, reverse := range []bool{false, true} {
				b, c, s, _ := closureFixture(t, "nested/a", "unrelated")
				s.Entries = s.Entries[1:]
				s.Entries[0].Size++ // independent drift survives
				narrow := s.Scopes[0]
				narrow.Prefix, narrow.EvidenceID, narrow.Status = "nested", "boundary", status
				if status == ObservationComplete {
					narrow.OwnerInstanceID = "foreign"
				}
				s.Scopes = append(s.Scopes, narrow)
				if reverse {
					s.Scopes[0], s.Scopes[1] = s.Scopes[1], s.Scopes[0]
				}
				a, err := CompareReferenceCatalog(b, c, s)
				if err != nil || a.SuppliedComparisonComplete || len(a.Gaps) == 0 || len(a.Differences) != 1 || a.Differences[0].Kind != DifferenceModified {
					t.Errorf("scope status=%d reverse=%v erased gap/drift: %+v %v", status, reverse, a, err)
				}
			}
		}
		b, c, s, _ := closureFixture(t, "a")
		narrow := s.Scopes[0]
		narrow.Prefix, narrow.Status = "node_modules/hidden", ObservationExcluded
		s.Scopes = append(s.Scopes, narrow)
		a, err := CompareReferenceCatalog(b, c, s)
		if err != nil || a.SuppliedComparisonComplete || len(a.Gaps) == 0 || len(a.Differences) != 1 {
			t.Fatalf("unvisited gap: %+v %v", a, err)
		}
	})
	t.Run("hierarchy-aliases-and-invalid-supplied-names", func(t *testing.T) {
		for _, name := range []string{"A", "a/child", "bad<name", "bad>name", "bad\"name", "bad|name", "bad?name", "bad*name"} {
			b, c, s, _ := closureFixture(t, "a", "unrelated")
			o := s.Entries[0]
			o.Name, o.EvidenceID = name, "extra"
			s.Entries = append(s.Entries, o)
			a, err := CompareReferenceCatalog(b, c, s)
			if err != nil || a.SuppliedComparisonComplete || len(a.Gaps) == 0 {
				t.Errorf("incoherent snapshot %q: %+v %v", name, a, err)
			}
			for _, d := range a.Differences {
				if d.EvidenceID == "extra" || ((name == "A" || name == "a/child") && d.EvidenceID == "a") {
					t.Errorf("related difference for %q qualified: %+v", name, a)
				}
			}
			if len(a.Differences) == 0 {
				t.Fatal("unrelated difference lost")
			}
		}
	})
	t.Run("context-claims-preserve-drift-all-renderers", func(t *testing.T) {
		b, c, s, _ := closureFixture(t, "a")
		s.Entries[0].Size++
		s.Scopes[0].Context = ContextPatch
		generated := s.Scopes[0]
		generated.Prefix, generated.Context, generated.EvidenceID = "a", ContextGenerated, "PRIVATE-context-source"
		s.Scopes = append(s.Scopes, generated)
		a, err := CompareReferenceCatalog(b, c, s)
		if err != nil || len(a.Differences) != 1 || a.Differences[0].Kind != DifferenceModified {
			t.Fatalf("context erased drift: %+v %v", a, err)
		}
		p := BuildPortableIntegrity(Assessment{Instances: []InstanceAssessment{a}})
		for _, format := range []string{"terminal", "json", "sarif"} {
			out, err := RenderIntegrity(p, format)
			if err != nil || !bytes.Contains(out, []byte("patch-context-claim")) || !bytes.Contains(out, []byte("generated-context-claim")) || !bytes.Contains(out, []byte("modified")) || bytes.Contains(out, []byte("PRIVATE")) {
				t.Fatalf("context output %s: %s %v", format, out, err)
			}
		}
	})
}

func TestCompareRejectsReferenceLinks(t *testing.T) {
	b, c, s := compareFixture()
	c.entries[0].Type = EntryLink
	a, e := CompareReferenceCatalog(b, c, s)
	if e != nil || len(a.Gaps) == 0 || a.SuppliedComparisonComplete || len(a.Differences) != 0 {
		t.Fatalf("link accepted: %+v %v", a, e)
	}
}
