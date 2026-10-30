package integrity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPortableOutputsRedactAllInputAndAreCoherent(t *testing.T) {
	secret := "PRIVATE-path-package-digest-source-error"
	a := Assessment{NativeQualification: secret, SuppliedComparisonComplete: true, Instances: []InstanceAssessment{{InstanceID: secret, Differences: []Difference{{Kind: DifferenceModified, InstanceID: secret, EntryID: secret, EvidenceID: secret}}, Gaps: []Gap{{Code: GapOwnership, InstanceID: secret, EvidenceID: secret}}}}}
	p := BuildPortableIntegrity(a)
	if !p.Experimental || p.NativeQualification != "not-run" || p.SuppliedComparisonComplete || len(p.Differences) != 1 || len(p.Gaps) != 1 || p.Differences[0].Instance != 1 || p.Differences[0].Entry != 1 || p.Differences[0].Evidence != 1 {
		t.Fatalf("portable: %+v", p)
	}
	for _, format := range []string{"terminal", "json", "sarif"} {
		out, e := RenderIntegrity(p, format)
		if e != nil || len(out) == 0 || bytes.Contains(out, []byte(secret)) || !bytes.Contains(out, []byte("not-run")) || !bytes.Contains(out, []byte("experimental")) {
			t.Fatalf("%s leaked/missing qualifier: %s %v", format, out, e)
		}
		if format == "json" {
			var v map[string]any
			if json.Unmarshal(out, &v) != nil || len(v["differences"].([]any)) != 1 || len(v["gaps"].([]any)) != 1 {
				t.Fatalf("invalid json: %s", out)
			}
		}
		if format == "sarif" {
			var v map[string]any
			if json.Unmarshal(out, &v) != nil || v["version"] != "2.1.0" || len(v["runs"].([]any)) != 1 {
				t.Fatalf("invalid sarif: %s", out)
			}
		}
	}
}
func TestPortableUnknownGapCannotBecomeComplete(t *testing.T) {
	a := Assessment{Instances: []InstanceAssessment{{InstanceID: "x", SuppliedComparisonComplete: true, Gaps: []Gap{{Code: GapCode("private unexpected gap"), InstanceID: "x"}}}}}
	p := BuildPortableIntegrity(a)
	if p.SuppliedComparisonComplete || len(p.Gaps) == 0 {
		t.Fatalf("unknown gap suppressed: %+v", p)
	}
}
func TestRenderRejectsUnknownFormatAndNeverEchoesUntrustedEnums(t *testing.T) {
	p := PortableIntegrityResult{NativeQualification: "SECRET", Differences: []PortableDifference{{Kind: DifferenceKind(255), Instance: 123}}, Gaps: []PortableGap{{Code: GapCode("SECRET"), Instance: 999}}}
	for _, f := range []string{"terminal", "json", "sarif"} {
		out, e := RenderIntegrity(p, f)
		if e != nil || strings.Contains(string(out), "SECRET") || strings.Contains(string(out), "123") || strings.Contains(string(out), "999") {
			t.Fatalf("unsafe %s: %s %v", f, out, e)
		}
	}
	if _, e := RenderIntegrity(p, "secret-format"); e == nil {
		t.Fatal("unknown format accepted")
	}
}
