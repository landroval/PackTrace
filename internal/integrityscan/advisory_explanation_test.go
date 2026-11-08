package integrityscan

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"packtrace/internal/intel"
)

func explanationOriginal(t *testing.T, summary, affected string) intel.SnapshotOriginalEvidence {
	t.Helper()
	title, _ := json.Marshal(summary)
	raw := []byte(`{"id":"GHSA-2345-6789-cfgh","modified":"2026-10-02T00:00:00Z","summary":` + string(title) + `,"affected":` + affected + `}`)
	doc, err := intel.ParseOSVRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	h, err := intel.ProjectOSVHeader(doc)
	if err != nil {
		t.Fatal(err)
	}
	a, err := intel.ProjectOSVAffected(doc)
	if err != nil {
		t.Fatal(err)
	}
	return intel.SnapshotOriginalEvidence{SHA256: sha256.Sum256(raw), Raw: raw, State: intel.SnapshotOriginalVerified, Header: h, Affected: a}
}

func TestAdvisoryExplanationUsesOwnMatchedCondition(t *testing.T) {
	r := explanationOriginal(t, "Owned parser permits unsafe input", `[{"package":{"ecosystem":"npm","name":"owned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]},{"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}]}]`)
	local := localAdvisoryExplanation(r, 1)
	if local.Summary != "Owned parser permits unsafe input" || len(local.Conditions) != 2 || ValidateLocalAdvisory(local) != nil {
		t.Fatal("original metadata lost", local)
	}
	d := AdvisoryDecision{Advisory: 1, Affected: 0, VersionOutcome: "match", FullyEvaluated: true, Support: []AdvisorySupport{{Version: -1, Range: 0}}}
	o := LocalObservation{Name: "owned", Version: "1.1.0"}
	why, next := localMatchReason(d, o, local)
	if !strings.Contains(why, "recorded affected interval") || !strings.Contains(next, "1.2.0") || strings.Contains(next, "9.0.0") {
		t.Fatal("wrong range or sibling package fix", why, next)
	}
	for _, mode := range []string{"partial", "wrong-range", "outside", "multiple"} {
		v := d
		q := o
		switch mode {
		case "partial":
			v.FullyEvaluated = false
		case "wrong-range":
			v.Support = []AdvisorySupport{{Version: -1, Range: 1}}
		case "outside":
			q.Version = "2.0.0"
		case "multiple":
			v.Support = append(append([]AdvisorySupport{}, v.Support...), AdvisorySupport{Version: 0, Range: -1})
		}
		_, next := localMatchReason(v, q, local)
		if strings.Contains(next, "fixed boundary") {
			t.Fatal("unsupported correction claim", mode, next)
		}
	}
}

func TestAdvisoryExplanationUnknownAndUnsafeTextStayUnknown(t *testing.T) {
	for _, title := range []string{"token=PRIVATE-secret", "See https://PRIVATE.invalid/record", "Read /home/PRIVATE/project", strings.Repeat("a", maxAdvisorySummary+1), "escape\x1b[31m"} {
		r := explanationOriginal(t, title, `[{"package":{"ecosystem":"npm","name":"owned"},"versions":["1.0.0"]}]`)
		v := localAdvisoryExplanation(r, 1)
		if v.Summary != "" || ValidateLocalAdvisory(v) != nil {
			t.Fatal("unsafe or unbounded summary exposed", title, v)
		}
	}
	r := explanationOriginal(t, "No simple correction", `[{"package":{"ecosystem":"npm","name":"owned"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"1.0.0"}]}]}]`)
	v := localAdvisoryExplanation(r, 1)
	if len(v.Conditions) != 0 {
		t.Fatal("last_affected became a fix")
	}
	d := AdvisoryDecision{Advisory: 1, Affected: 0, VersionOutcome: "match", FullyEvaluated: true, Support: []AdvisorySupport{{Version: -1, Range: 0}}}
	_, next := localMatchReason(d, LocalObservation{Version: "1.0.0"}, v)
	if strings.Contains(next, "fixed boundary") {
		t.Fatal("invented fix")
	}
	v.Summary = "bad\nline"
	if ValidateLocalAdvisory(v) == nil {
		t.Fatal("forged control text admitted")
	}
}

func TestAdvisoryExplanationLimitsAndExplicitVersion(t *testing.T) {
	r := explanationOriginal(t, "Owned exact-version advisory", `[{"package":{"ecosystem":"npm","name":"owned"},"versions":["1.0.0","1.1.0","1.2.0","1.3.0","1.4.0","1.5.0","1.6.0","1.7.0","1.8.0"]}]`)
	v := localAdvisoryExplanation(r, 1)
	if len(v.Conditions) != maxAdvisoryConditions || !v.ExplanationLimited || ValidateLocalAdvisory(v) != nil {
		t.Fatal("metadata budget not retained", v)
	}
	d := AdvisoryDecision{Advisory: 1, Affected: 0, VersionOutcome: "match", Support: []AdvisorySupport{{Version: 0, Range: -1}}}
	why, next := localMatchReason(d, LocalObservation{Version: "1.0.0"}, v)
	if !strings.Contains(why, "exact version") || strings.Contains(next, "fixed boundary") {
		t.Fatal("explicit version promoted to remediation", why, next)
	}
	v.Conditions = append(v.Conditions, v.Conditions[0])
	if ValidateLocalAdvisory(v) == nil {
		t.Fatal("duplicate/oversized conditions admitted")
	}
}
