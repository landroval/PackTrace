package integrityscan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/projectinventory"
)

// Opt-in offline evidence collector. It consumes only an explicitly supplied
// owned restored copy; it never acquires, extracts, repairs or executes packages.
func TestPublicPilotOfflineEvidence(t *testing.T) {
	base := os.Getenv("PACKTRACE_PILOT_CASE")
	output := os.Getenv("PACKTRACE_PILOT_EVIDENCE")
	if base == "" || output == "" {
		t.Skip("explicit owned pilot copy and external evidence directory required")
	}
	raw, e := os.ReadFile(filepath.Join(base, "references/policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := ParsePolicy(raw)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := Configure(cli.ScanArgumentRequest{PolicyPath: "policy.json", TrustedPolicyDigest: sourceSRI(raw), Manager: "npm", Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity, Privacy: "portable", Output: "-"}, p)
	if e != nil {
		t.Fatal(e)
	}
	plan.IntegrityProfile = VerifyNPMProfile
	var records []Record
	var inventory projectinventory.Result
	summary, e := AcquireWithInventory(context.Background(), filepath.Join(base, "target"), filepath.Join(base, "references"), sourceSRI(raw), plan, func(r Record) error {
		if err := ValidateRecord(plan, r, sourceSRI(raw)); err != nil {
			return err
		}
		records = append(records, r)
		return nil
	}, func(inv projectinventory.Result) error { inventory = inv; return nil })
	if e != nil {
		t.Fatal(e)
	}
	type support struct {
		Index           int
		Location        string
		Legacy          bool
		Verify          bool
		Entries         int
		CompressedBytes int64
		ObservedSRI     string
	}
	var supports []support
	for i, r := range records {
		b, gaps := integrity.ResolveReferenceBinding(Binding(plan, i, r.Lock, sourceSRI(raw)))
		if len(gaps) != 0 {
			t.Fatal(gaps)
		}
		archive, e := os.ReadFile(filepath.Join(base, "references", p.References[i].Archive))
		if e != nil {
			t.Fatal(e)
		}
		_, le := integrity.InspectReferenceArchive(context.Background(), b, bytes.NewReader(archive), integrity.Limits{})
		catalog, ce := integrity.InspectReferenceArchiveProfile(context.Background(), b, bytes.NewReader(archive), integrity.Limits{}, integrity.ArchiveVerifyNPM)
		receipt := catalog.Receipt()
		supports = append(supports, support{i + 1, p.References[i].Location, le == nil, ce == nil, len(catalog.Entries()), catalog.CompressedRead, receipt.ObservedSRI})
		if ce != nil || catalog.CompressedRead != int64(len(archive)) || len(catalog.Entries()) == 0 {
			t.Errorf("instance %d archive unsupported: %v", i+1, ce)
		}
	}
	save := func(name string, v any) {
		t.Helper()
		data, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(output, name), append(data, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	save("per-instance-support.json", supports)
	save("native-records.json", records)
	save("native-summary.json", summary)
	save("native-inventory.json", inventory)
	if len(records) != 160 {
		t.Fatalf("expected original 160 instances, got %d", len(records))
	}
	for i, r := range records {
		if !r.Assessment.SuppliedComparisonComplete || len(r.Assessment.Gaps) != 0 {
			t.Errorf("instance %d: %+v", i+1, r.Assessment.Gaps)
		}
	}
}
