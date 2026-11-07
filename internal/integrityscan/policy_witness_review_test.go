package integrityscan

import (
	"crypto/sha256"
	"strconv"
	"testing"

	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

func TestReviewAdvisoryRejectsIntegrityWitnessIDs(t *testing.T) {
	plan, inv, advisories, m := engineFixture(t)
	if ValidatePolicyMaterial(plan, inv, nil, advisories, m) != nil {
		t.Fatal("honest advisory fixture refused")
	}
	for _, field := range []string{"reference", "observed"} {
		bad := m
		if field == "reference" {
			bad.ReferenceEntryID = "1"
		} else {
			bad.ObservedEntryID = "instance-1:observed:1"
		}
		if ValidatePolicyMaterial(plan, inv, nil, advisories, bad) == nil {
			t.Fatal("advisory admitted integrity transport IDs")
		}
	}
}

func TestReviewProducerWitnessBoundAndInstalledEndpoint(t *testing.T) {
	catalog, binding, sri := policyEvidenceCatalog(t)
	inv := policyEvidenceFixture()
	p, ok := BuildProjectEvidence(inv)
	if !ok {
		t.Fatal("project fixture")
	}
	plan := Plan{Policy: Policy{References: []Reference{{Name: "p", Version: "1.0.0", Origin: "o", Location: "node_modules/p", ExpectedSRI: sri, Context: "none"}}}}
	snapshot := integrity.InstalledSnapshot{Scopes: []integrity.InstalledScope{{InstanceID: instanceID(0), OwnerInstanceID: instanceID(0), EvidenceID: instanceID(0) + ":scope", Enumerated: true, OwnershipKnown: true, Status: integrity.ObservationComplete}}}
	// Real authored comparison: one missing reference file plus 4097 added files.
	for i := 1; i <= 4097; i++ {
		snapshot.Entries = append(snapshot.Entries, integrity.InstalledEntry{InstanceID: instanceID(0), OwnerInstanceID: instanceID(0), EvidenceID: instanceID(0) + ":observed:" + strconv.Itoa(i), Name: "added-" + strconv.Itoa(i), Type: integrity.EntryFile, SHA256: sha256.Sum256(nil), Status: integrity.ObservationComplete})
	}
	assessment, err := integrity.CompareReferenceCatalog(binding, catalog, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(assessment.Differences) != 4098 {
		t.Fatal("comparison did not exercise cap", len(assessment.Differences))
	}
	record := Record{Assessment: assessment}
	var rows []PolicyMaterial
	if err := emitIntegrityPolicyEvidence(p, plan, &record, indexPolicyInventory(inv), catalog, snapshot, func(m PolicyMaterial) error { rows = append(rows, m); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4096 || len(record.PolicyWitnesses) != 4096 || record.PolicyObservation != 2 || !validPolicyWitnesses(record) {
		t.Fatal("witness bound/endpoint", len(rows), len(record.PolicyWitnesses), record.PolicyObservation)
	}
	if !record.PolicyMaterialLimited {
		t.Fatal("producer omitted eligible evidence without propagating its limit")
	}
	exact := record
	exact.Assessment.Differences = assessment.Differences[:4096]
	if err := emitIntegrityPolicyEvidence(p, plan, &exact, indexPolicyInventory(inv), catalog, snapshot, func(PolicyMaterial) error { return nil }); err != nil || exact.PolicyMaterialLimited || len(exact.PolicyWitnesses) != 4096 {
		t.Fatal("exactly full witness budget was mislabeled limited", err)
	}
	for i, m := range rows {
		w := record.PolicyWitnesses[i]
		d := assessment.Differences[w.Difference]
		if w.Fingerprint != PolicyDifferenceFingerprint(m) || w.EntryID != d.EntryID || w.EvidenceID != d.EvidenceID {
			t.Fatal("cap cross-wired witnesses")
		}
	}
	for name, mutate := range map[string]func(*projectinventory.Result){
		"duplicate installed": func(inv *projectinventory.Result) {
			inv.Model.Observations = append(inv.Model.Observations, inv.Model.Observations[1])
		},
		"wrong manifest source": func(inv *projectinventory.Result) { inv.Model.Evidence[2].Location = "node_modules/other/package.json" },
		"wrong metadata":        func(inv *projectinventory.Result) { inv.Model.Evidence[3].Location = "node_modules/other" },
		"incomplete manifest":   func(inv *projectinventory.Result) { inv.Model.Evidence[2].Complete = false },
		"incomplete metadata":   func(inv *projectinventory.Result) { inv.Model.Evidence[3].Complete = false },
		"wrong package":         func(inv *projectinventory.Result) { inv.Model.Observations[1].Name = "other" },
		"wrong physical target": func(inv *projectinventory.Result) {
			inv.Model.Observations[1].Fields["physical-target"] = "node_modules/other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := policyEvidenceFixture()
			mutate(&bad)
			r := record
			count := 0
			if err := emitIntegrityPolicyEvidence(p, plan, &r, indexPolicyInventory(bad), catalog, snapshot, func(PolicyMaterial) error { count++; return nil }); err != nil {
				t.Fatal(err)
			}
			if count != 0 || r.PolicyObservation != 0 || len(r.PolicyWitnesses) != 0 {
				t.Fatal("unassociated producer endpoint retained material or stale witnesses")
			}
		})
	}
}
