package integrity

import "testing"

func TestReferenceCatalogReceiptBindsOriginalCatalog(t *testing.T) {
	b, c, _, raw := closureFixture(t, "a")
	receipt := c.Receipt()
	if !ValidateReferenceCatalogReceipt(b, receipt) {
		t.Fatal("actual verified catalog lost")
	}
	if ValidateReferenceCatalogReceipt(b, (ReferenceCatalog{}).Receipt()) {
		t.Fatal("empty catalog granted receipt")
	}
	for name, mutate := range map[string]func(*ReferenceCatalogReceipt){
		"instance": func(r *ReferenceCatalogReceipt) { r.InstanceID = "other" },
		"binding":  func(r *ReferenceCatalogReceipt) { r.Binding[0] ^= 1 },
		"digest": func(r *ReferenceCatalogReceipt) {
			r.ObservedSRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := receipt
			mutate(&r)
			if ValidateReferenceCatalogReceipt(b, r) {
				t.Fatal("reassigned catalog")
			}
		})
	}
	in := closureInput(raw)
	in.Lockfile.SourceHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	other, gaps := ResolveReferenceBinding(in)
	if len(gaps) != 0 {
		t.Fatal(gaps)
	}
	if ValidateReferenceCatalogReceipt(other, receipt) {
		t.Fatal("changed source inherited catalog binding")
	}
}

func TestReferenceOwnedNestedDirectoriesKeepBoundaries(t *testing.T) {
	for _, mode := range []string{"owned", "unknown", "unstable-namespace", "ordinary-file", "published-overlap"} {
		t.Run(mode, func(t *testing.T) {
			names := []string{"a"}
			if mode == "published-overlap" {
				names = append(names, "node_modules/child/content")
			}
			b, c, s, _ := closureFixture(t, names...)
			id := b.InstanceID()
			s.Entries = append(s.Entries, InstalledEntry{Name: "node_modules", EvidenceID: "namespace", InstanceID: id, OwnerInstanceID: id, Type: EntryDirectory, Status: ObservationComplete})
			scope := InstalledScope{Prefix: "node_modules/child", InstanceID: id, OwnerInstanceID: "child", EvidenceID: "nested", OwnershipKnown: true, Enumerated: true, Status: ObservationComplete}
			if mode == "unknown" {
				scope.OwnershipKnown = false
			}
			s.Scopes = append(s.Scopes, scope)
			if mode == "unstable-namespace" {
				s.Entries[len(s.Entries)-1].Status = ObservationUnstable
			}
			if mode == "ordinary-file" {
				s.Entries = append(s.Entries, InstalledEntry{Name: "node_modules/unmapped", EvidenceID: "ordinary", InstanceID: id, OwnerInstanceID: id, Type: EntryFile, Size: 1, Status: ObservationComplete})
			}
			a, err := CompareReferenceCatalogOwned(b, c, s)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "owned" {
				if !a.SuppliedComparisonComplete || len(a.Gaps) != 0 || len(a.Differences) != 1 || a.Differences[0].Kind != DifferenceUnchanged {
					t.Fatalf("nested equality lost: %+v", a)
				}
			} else if mode == "ordinary-file" {
				found := false
				for _, d := range a.Differences {
					found = found || d.Kind == DifferenceAdded && d.EvidenceID == "ordinary"
				}
				if !found {
					t.Fatal("regular content excluded")
				}
			} else if a.SuppliedComparisonComplete || len(a.Gaps) == 0 {
				t.Fatal("uncertain/overlapping ownership completed")
			}
			historical, err := CompareReferenceCatalog(b, c, s)
			if err != nil || historical.SuppliedComparisonComplete {
				t.Fatal("historical supplied-scope contract changed")
			}
		})
	}
}
