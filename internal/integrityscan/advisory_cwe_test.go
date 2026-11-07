package integrityscan

import (
	"strings"
	"testing"
)

func TestOpenSSFDescriptiveCWEsDoNotClassifyOrCorrect(t *testing.T) {
	cwe := func() map[string]any {
		return map[string]any{"cweId": "CWE-506", "name": "Embedded Malicious Code", "description": "Authored informational metadata, not a classification rule."}
	}
	for _, id := range []string{"CWE-506", "CWE-79"} {
		doc := profileDocument("openssf")
		entry := cwe()
		entry["cweId"] = id
		profileDB(doc)["cwes"] = []any{entry}
		if q := qualifyProfileDocument(t, doc, 0); q.Profile != "osv-openssf-malicious-v1" || q.Category != "malicious" || len(q.Gaps) != 0 {
			t.Fatal("bounded descriptive CWE rejected", q)
		}
		profileDB(doc)["source"] = "https://example.invalid/MAL-2026-1.json"
		if q := qualifyProfileDocument(t, doc, 0); q.Profile != "unknown" {
			t.Fatal("CWE became source authority", q)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { c["withdrawn_versions"] = []string{"1.0.0"} },
		func(c map[string]any) { delete(c, "description") },
		func(c map[string]any) { c["cweId"] = "CWE-0" },
		func(c map[string]any) { c["cweId"] = "PRIVATE-arbitrary" },
		func(c map[string]any) { c["name"] = strings.Repeat("x", 257) },
		func(c map[string]any) { c["description"] = strings.Repeat("x", 4097) },
		func(c map[string]any) { c["description"] = nil },
	} {
		doc := profileDocument("openssf")
		entry := cwe()
		mutate(entry)
		profileDB(doc)["cwes"] = []any{entry}
		if q := qualifyProfileDocument(t, doc, 0); q.Profile != "unknown" {
			t.Fatal("unknown/oversized descriptive shape accepted", q)
		}
	}
	doc := profileDocument("github-reviewed")
	profileDB(doc)["cwes"] = []any{cwe()}
	if q := qualifyProfileDocument(t, doc, 0); q.Profile != "unknown" {
		t.Fatal("OpenSSF-specific shape widened another provider", q)
	}
	doc = profileDocument("openssf")
	profileDB(doc)["cwes"] = []any{cwe()}
	doc["database_specific"].(map[string]any)["withdrawn_versions"] = []string{"1.0.0"}
	if q := qualifyProfileDocument(t, doc, 0); q.Profile != "unknown" {
		t.Fatal("informational CWE bypassed correction gate", q)
	}
}
