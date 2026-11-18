package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// Real supervised CLI: source policy phase, normalized acquire config, private
// originals, native slot bindings, scope receipts and whole-inventory join.
func TestScanCompactPolicyWholeIntegrity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("owned subprocess fixtures")
	}
	for _, mode := range []string{"equal", "modified", "missing-archive", "unavailable-manifest", "identity-conflict"} {
		t.Run(mode, func(t *testing.T) {
			target, policy, p, _ := wholeIntegrityFixture(t, "npm", mode)
			r := p.References[0]
			if r.Location != r.LockKey {
				t.Fatal("fixture not representable")
			}
			b, _ := json.Marshal(p)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(b, &fields)
			delete(fields, "references")
			fields["referenceTable"], _ = json.Marshal(map[string]any{"format": "same-location-lockkey-v1", "classification": r.Classification, "context": r.Context, "rows": [][6]string{{r.Location, r.Name, r.Version, r.Origin, r.ExpectedSRI, r.Archive}}})
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policy, data, 0600); err != nil {
				t.Fatal(err)
			}
			before := wholeIntegrityTree(t, target)
			sum := sha256.Sum256(data)
			for _, privacy := range []string{"portable", "local"} {
				t.Run(privacy, func(t *testing.T) {
					report, raw := runPolicyAcceptanceJSON(t, "--policy", policy, "--trusted-policy-digest", "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), "--checks", "integrity", "--privacy", privacy, "--format", "json", target)
					if dir := os.Getenv("PACKTRACE_COMPACT_REPORTS"); dir != "" {
						f, err := os.OpenFile(filepath.Join(dir, mode+"-"+privacy+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
						if err != nil {
							t.Fatal(err)
						}
						_, err = f.Write([]byte(raw))
						closeErr := f.Close()
						if err != nil || closeErr != nil {
							t.Fatal(err, closeErr)
						}
					}
					want := "incomplete"
					if mode == "equal" || mode == "modified" {
						want = "completed"
					}
					wholeIntegrityCoverage(t, report, "integrity", want)
					wholeIntegrityCoverage(t, report, "native-qualification", "incomplete")
					if report.Instances != 1 || report.Inventory == nil || report.Inventory.Counts.Installed != 1 {
						t.Fatalf("lost explicit instance: %s", raw)
					}
					if mode == "equal" || mode == "modified" {
						if !report.Comparison.SuppliedComparisonComplete || len(report.Comparison.Gaps) != 0 || report.ObservedEntries != 3 {
							t.Fatalf("comparison receipt lost: %s", raw)
						}
						o := report.Inventory.Observations[3]
						if o.Class != "installed" || o.Source == 0 || o.MetadataEvidence == 0 || o.Source == o.MetadataEvidence {
							t.Fatalf("physical slot join lost: %s", raw)
						}
						source := report.Inventory.Evidence[o.Source-1]
						metadata := report.Inventory.Evidence[o.MetadataEvidence-1]
						if source.MetadataEvidence != metadata.ID || source.Method != "native-input-lease" || metadata.Method != "native-metadata-lease" {
							t.Fatalf("native binding lost: %s", raw)
						}
					}
					if mode == "equal" && report.Findings != 0 {
						t.Fatalf("unexpected finding: %s", raw)
					}
					if mode == "modified" && report.Findings == 0 {
						t.Fatalf("altered bytes hidden: %s", raw)
					}
					if mode == "missing-archive" && (report.Comparison.SuppliedComparisonComplete || report.ObservedEntries != 0) {
						t.Fatalf("missing evidence granted comparison: %s", raw)
					}
					if !reflect.DeepEqual(before, wholeIntegrityTree(t, target)) {
						t.Fatal("target changed")
					}
					after, err := os.ReadFile(filepath.Clean(policy))
					if err != nil || !reflect.DeepEqual(after, data) {
						t.Fatal("policy source changed", err)
					}
				})
			}
		})
	}
}
