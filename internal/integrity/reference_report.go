package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// BuildPortableIntegrity projects only allowlisted labels and positional references.
// A complete supplied comparison is never a completed native scan.
func BuildPortableIntegrity(a Assessment) PortableIntegrityResult {
	p := PortableIntegrityResult{NativeQualification: "not-run", Experimental: true}
	instances, entries, evidence := map[string]int{}, map[string]int{}, map[string]int{}
	index := func(m map[string]int, key string) int {
		if key == "" {
			return 0
		}
		if m[key] == 0 {
			m[key] = len(m) + 1
		}
		return m[key]
	}
	for _, ia := range a.Instances {
		instance := index(instances, ia.InstanceID)
		for _, d := range ia.Differences {
			if differenceLabel(d.Kind) == "" {
				continue
			}
			p.Differences = append(p.Differences, PortableDifference{Kind: d.Kind, Instance: instance, Entry: index(entries, d.EntryID), Evidence: index(evidence, d.EvidenceID)})
		}
		for _, c := range ia.Contexts {
			if contextLabel(c.Kind) != "" {
				p.Contexts = append(p.Contexts, PortableContext{Kind: c.Kind, Instance: instance, Evidence: index(evidence, c.EvidenceID)})
			}
		}
		for _, g := range ia.Gaps {
			code := g.Code
			if gapLabel(code) == "" {
				code = GapObservation
			}
			p.Gaps = append(p.Gaps, PortableGap{Code: code, Instance: instance, Entry: index(entries, g.EntryID), Evidence: index(evidence, g.EvidenceID)})
		}
	}
	for _, g := range a.Gaps {
		code := g.Code
		if gapLabel(code) == "" {
			code = GapObservation
		}
		p.Gaps = append(p.Gaps, PortableGap{Code: code, Instance: index(instances, g.InstanceID), Entry: index(entries, g.EntryID), Evidence: index(evidence, g.EvidenceID)})
	}
	p.SuppliedComparisonComplete = len(p.Gaps) == 0 && len(a.Gaps) == 0 && len(a.Instances) > 0
	for _, ia := range a.Instances {
		if !ia.SuppliedComparisonComplete {
			p.SuppliedComparisonComplete = false
		}
	}
	return p
}

func differenceLabel(k DifferenceKind) string {
	switch k {
	case DifferenceUnchanged:
		return "unchanged"
	case DifferenceModified:
		return "modified"
	case DifferenceMissing:
		return "missing"
	case DifferenceAdded:
		return "added"
	case DifferenceTypeChanged:
		return "type-changed"
	}
	return ""
}
func contextLabel(k ContextKind) string {
	switch k {
	case ContextPatch:
		return "patch-context-claim"
	case ContextGenerated:
		return "generated-context-claim"
	}
	return ""
}
func gapLabel(k GapCode) string {
	switch k {
	case GapBinding, GapReference, GapObservation, GapOwnership, GapUnsupported, GapTruncated:
		return string(k)
	}
	return ""
}

// RenderIntegrity emits only fixed labels and derived positions, not source claims.
func RenderIntegrity(p PortableIntegrityResult, format string) ([]byte, error) {
	type item struct {
		RuleID   string `json:"ruleId"`
		Level    string `json:"level"`
		Message  string `json:"message"`
		Instance int    `json:"instance,omitempty"`
		Entry    int    `json:"entry,omitempty"`
		Evidence int    `json:"evidence,omitempty"`
	}
	items := make([]item, 0, len(p.Differences)+len(p.Gaps))
	for _, d := range p.Differences {
		if label := differenceLabel(d.Kind); label != "" {
			level := "note"
			if d.Kind != DifferenceUnchanged {
				level = "warning"
			}
			items = append(items, item{"PT-DIFF-" + strings.ToUpper(label), level, "experimental supplied-evidence " + label, safePosition(d.Instance), safePosition(d.Entry), safePosition(d.Evidence)})
		}
	}
	differenceCount := len(items)
	for _, g := range p.Gaps {
		if label := gapLabel(g.Code); label != "" {
			items = append(items, item{"PT-GAP-" + strings.ToUpper(label), "warning", "experimental supplied-evidence gap: " + label, safePosition(g.Instance), safePosition(g.Entry), safePosition(g.Evidence)})
		}
	}
	gapEnd := len(items)
	for _, c := range p.Contexts {
		if label := contextLabel(c.Kind); label != "" {
			items = append(items, item{"PT-CLAIM-" + strings.ToUpper(label), "note", "experimental supplied-evidence " + label, safePosition(c.Instance), 0, safePosition(c.Evidence)})
		}
	}
	switch format {
	case "terminal":
		var out strings.Builder
		out.WriteString("experimental supplied evidence; native qualification: not-run; production scan: incomplete\n")
		for _, i := range items {
			fmt.Fprintf(&out, "%s %s instance=%d entry=%d evidence=%d\n", i.RuleID, i.Message, i.Instance, i.Entry, i.Evidence)
		}
		return []byte(out.String()), nil
	case "json":
		return json.Marshal(struct {
			Experimental               bool   `json:"experimental"`
			NativeQualification        string `json:"nativeQualification"`
			ScanCoverage               string `json:"scanCoverage"`
			SuppliedComparisonComplete bool   `json:"suppliedComparisonComplete"`
			Differences                []item `json:"differences"`
			Gaps                       []item `json:"gaps"`
			Claims                     []item `json:"claims"`
		}{true, "not-run", "incomplete", len(p.Gaps) == 0 && p.SuppliedComparisonComplete, items[:differenceCount], items[differenceCount:gapEnd], items[gapEnd:]})
	case "sarif":
		type sarifMessage struct {
			Text string `json:"text"`
		}
		type sarifResult struct {
			RuleID     string       `json:"ruleId"`
			Level      string       `json:"level"`
			Message    sarifMessage `json:"message"`
			Properties item         `json:"properties"`
		}
		results := make([]sarifResult, 0, len(items))
		for _, i := range items {
			results = append(results, sarifResult{i.RuleID, i.Level, sarifMessage{i.Message}, i})
		}
		return json.Marshal(struct {
			Schema  string `json:"$schema"`
			Version string `json:"version"`
			Runs    []any  `json:"runs"`
		}{"https://json.schemastore.org/sarif-2.1.0.json", "2.1.0", []any{struct {
			Tool       any           `json:"tool"`
			Results    []sarifResult `json:"results"`
			Properties any           `json:"properties"`
		}{struct {
			Driver any `json:"driver"`
		}{struct {
			Name string `json:"name"`
		}{"PackTrace experimental supplied-evidence integrity"}}, results, struct {
			Experimental        bool   `json:"experimental"`
			NativeQualification string `json:"nativeQualification"`
			ScanCoverage        string `json:"scanCoverage"`
		}{true, "not-run", "incomplete"}}}})
	default:
		return nil, errors.New("unsupported integrity render format")
	}
}
func safePosition(n int) int {
	if n < 1 || n > 1000000 {
		return 0
	}
	return n
}
