package integrityscan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"packtrace/internal/intel"
)

var profileNow = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

func profileEvidence(t *testing.T, raw []byte) intel.SnapshotOriginalEvidence {
	t.Helper()
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
	times, err := intel.ProjectOSVTimes(doc)
	if err != nil {
		t.Fatal(err)
	}
	return intel.SnapshotOriginalEvidence{SHA256: doc.SHA256, Raw: raw, State: intel.SnapshotOriginalVerified, Header: h, Affected: a, Times: times}
}

func profileDocument(kind string) map[string]any {
	id := "GHSA-2234-fmw7-43wr"
	source := "https://github.com/github/advisory-database/blob/main/advisories/" + kind + "/2026/10/" + id + "/" + id + ".json"
	db := map[string]any{"github_reviewed": true, "github_reviewed_at": "2026-10-02T00:00:00Z", "nvd_published_at": nil, "cwe_ids": []string{"CWE-506"}, "severity": "HIGH"}
	if kind == "openssf" {
		id = "MAL-2026-1"
		source = "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/left-pad/" + id + ".json"
		db = map[string]any{"malicious-packages-origins": []any{map[string]any{"source": "ghsa-malware", "id": "GHSA-2234-fmw7-43wr", "sha256": strings.Repeat("a", 64), "import_time": "2026-10-02T00:00:00Z", "modified_time": "2026-10-01T00:00:00Z"}}}
	}
	return map[string]any{"id": id, "modified": "2026-10-02T00:00:00Z", "published": "2026-10-01T00:00:00Z", "summary": "Informational only", "database_specific": db, "affected": []any{map[string]any{"package": map[string]any{"ecosystem": "npm", "name": "left-pad"}, "versions": []string{"1.0.0"}, "database_specific": map[string]any{"source": source, "cwes": []string{"CWE-506"}}}}}
}

func profileSlot(doc map[string]any) map[string]any {
	return doc["affected"].([]any)[0].(map[string]any)
}
func profileDB(doc map[string]any) map[string]any {
	return profileSlot(doc)["database_specific"].(map[string]any)
}
func qualifyProfileDocument(t *testing.T, doc map[string]any, slot int) AdvisoryQualification {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return qualifyAdvisory(profileEvidence(t, raw), slot, profileNow)
}

func TestQualifyAdvisorySourceProfiles(t *testing.T) {
	for _, tc := range []struct{ kind, category, profile string }{
		{"github-reviewed", "vulnerability", "osv-github-reviewed-v1"},
		{"malware", "malicious", "osv-github-malware-v1"},
		{"openssf", "malicious", "osv-openssf-malicious-v1"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			got := qualifyProfileDocument(t, profileDocument(tc.kind), 0)
			if got.Category != tc.category || got.Profile != tc.profile || got.Activity != "not-withdrawn" || len(got.Gaps) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
	got := qualifyAdvisory(profileEvidence(t, []byte(matchingRaw)), 0, profileNow)
	if got.Category != "malicious" || got.Profile != "openssf-malicious-v1" || len(got.Gaps) != 0 {
		t.Fatal(got)
	}
	// The OSV source path supports scoped npm names without percent encoding.
	doc := profileDocument("openssf")
	profileSlot(doc)["package"].(map[string]any)["name"] = "@scope/pkg"
	profileDB(doc)["source"] = strings.ReplaceAll(profileDB(doc)["source"].(string), "/left-pad/", "/@scope/pkg/")
	if got := qualifyProfileDocument(t, doc, 0); got.Profile != "osv-openssf-malicious-v1" {
		t.Fatal(got)
	}
}

func TestQualifyAdvisoryRejectsSpoofedAndConflictingSources(t *testing.T) {
	base := profileDB(profileDocument("github-reviewed"))["source"].(string)
	for _, source := range []string{
		strings.Replace(base, "github.com/", "github.com.evil/", 1),
		strings.Replace(base, "github.com/", "github.com:443/", 1),
		strings.Replace(base, "github.com/", "user@github.com/", 1),
		strings.Replace(base, "https:", "http:", 1), base + "?raw=1", base + "?", base + "#", base + "#type=malware",
		strings.Replace(base, "github.com", "GITHUB.COM", 1),
		strings.Replace(base, "github-reviewed", "unreviewed", 1),
		strings.Replace(base, "/2026/10/", "/2026/13/", 1),
		strings.Replace(base, "/2026/10/", "/2026/1/", 1),
		strings.Replace(base, "github-reviewed", "%67ithub-reviewed", 1),
		strings.Replace(base, "blob/main", "blob/HEAD", 1),
		strings.Replace(base, "/GHSA-2234-fmw7-43wr/", "/GHSA-2234-fmw7-43wx/", 1),
		strings.Replace(base, "/GHSA-2234-fmw7-43wr/", "/", 1), // no evidenced direct-leaf layout
		strings.Replace(base, "/2026/10/", "/2026/10/../10/", 1),
	} {
		doc := profileDocument("github-reviewed")
		profileDB(doc)["source"] = source
		if got := qualifyProfileDocument(t, doc, 0); got.Category != "unknown" || got.Profile != "unknown" {
			t.Errorf("accepted %q: %+v", source, got)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["id"] = "GHSA-2234-fmw7-43wx" },
		func(d map[string]any) { profileDB(d)["source"] = nil },
		func(d map[string]any) { delete(profileDB(d), "source") },
		func(d map[string]any) { profileDB(d)["type"] = "malicious" },
		func(d map[string]any) { d["database_specific"].(map[string]any)["type"] = "malicious" },
		func(d map[string]any) {
			d["affected"] = append(d["affected"].([]any), profileSlot(profileDocument("malware")))
		},
	} {
		doc := profileDocument("github-reviewed")
		mutate(doc)
		if got := qualifyProfileDocument(t, doc, 0); got.Category != "unknown" {
			t.Fatal(got)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { profileSlot(d)["package"].(map[string]any)["name"] = "another" },
		func(d map[string]any) {
			profileDB(d)["source"] = strings.Replace(profileDB(d)["source"].(string), "MAL-2026-1.json", "MAL-2026-2.json", 1)
		},
		func(d map[string]any) { d["id"] = "GHSA-2234-fmw7-43wr" },
	} {
		doc := profileDocument("openssf")
		mutate(doc)
		if got := qualifyProfileDocument(t, doc, 0); got.Category != "unknown" {
			t.Fatal(got)
		}
	}
}

func TestQualifyAdvisoryExtensionsAndInformationAreNotAuthority(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["false_positive_versions"] = []string{"1.0.0"} },
		func(d map[string]any) { d["database_specific"].(map[string]any)["corrections"] = []string{"1.0.0"} },
		func(d map[string]any) { profileDB(d)["excluded"] = []string{"1.0.0"} },
		func(d map[string]any) { profileSlot(d)["ecosystem_specific"] = map[string]any{"correction": true} },
		func(d map[string]any) {
			profileSlot(d)["ranges"] = []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0"}}, "database_specific": map[string]any{"exclusions": []string{"1.0.0"}}}}
		},
		func(d map[string]any) { profileDB(d)["cwes"] = nil },
		func(d map[string]any) { profileSlot(d)["ecosystem_specific"] = map[string]any{"severity": nil} },
		func(d map[string]any) { d["database_specific"].(map[string]any)["github_reviewed"] = "true" },
		func(d map[string]any) { d["database_specific"].(map[string]any)["cwe_ids"] = []any{1} },
		func(d map[string]any) { d["database_specific"].(map[string]any)["severity"] = nil },
	} {
		doc := profileDocument("github-reviewed")
		mutate(doc)
		got := qualifyProfileDocument(t, doc, 0)
		if got.Category != "unknown" || !hasMatchingGap(got.Gaps, "correction-unsupported") {
			t.Fatal(got)
		}
	}
	doc := profileDocument("github-reviewed")
	doc["database_specific"].(map[string]any)["github_reviewed"] = false
	doc["database_specific"].(map[string]any)["severity"] = "LOW"
	doc["summary"] = "malware"
	profileSlot(doc)["ecosystem_specific"] = map[string]any{"severity": "HIGH"}
	if got := qualifyProfileDocument(t, doc, 0); got.Category != "vulnerability" {
		t.Fatal(got)
	}
	profileDB(doc)["source"] = "https://cna.erlef.org/osv/GHSA-2234-fmw7-43wr.json"
	if got := qualifyProfileDocument(t, doc, 0); got.Category != "unknown" {
		t.Fatal(got)
	}
}

func TestQualifyAdvisoryActivity(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
		remove      bool
		want        string
	}{
		{"optional-absent", "published", nil, true, "not-withdrawn"},
		{"optional-null", "published", nil, false, "unknown"},
		{"optional-future", "published", "2027-01-01T00:00:00Z", false, "unknown"},
		{"optional-after-modified", "published", "2026-10-02T12:00:00Z", false, "unknown"},
		{"modified-future", "modified", "2027-01-01T00:00:00Z", false, "unknown"},
		{"withdrawn", "withdrawn", "2026-10-02T00:00:00Z", false, "withdrawn"},
		{"withdrawn-before-published", "withdrawn", "2026-09-30T00:00:00Z", false, "unknown"},
		{"withdrawn-after-modified", "withdrawn", "2026-10-02T12:00:00Z", false, "unknown"},
		{"withdrawn-future", "withdrawn", "2027-01-01T00:00:00Z", false, "unknown"},
		{"withdrawn-null", "withdrawn", nil, false, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := profileDocument("github-reviewed")
			if tc.remove {
				delete(doc, tc.field)
			} else {
				doc[tc.field] = tc.value
			}
			got := qualifyProfileDocument(t, doc, 0)
			if got.Category != "vulnerability" || got.Activity != tc.want || hasMatchingGap(got.Gaps, "activity-unknown") != (tc.want == "unknown") {
				t.Fatal(got)
			}
		})
	}
	doc := profileDocument("github-reviewed")
	delete(doc, "published")
	doc["withdrawn"] = "2026-09-30T00:00:00Z"
	if got := qualifyProfileDocument(t, doc, 0); got.Activity != "withdrawn" {
		t.Fatal(got)
	}
}

func TestAdvisoryProfileMissingRequiredModified(t *testing.T) {
	// These originals are rejected before verified-evidence construction. Also
	// keep the activity helper conservative for absent/null projections.
	for _, raw := range []string{`{"id":"SYNTHETIC"}`, `{"id":"SYNTHETIC","modified":null}`} {
		if _, err := intel.ParseOSVRecord([]byte(raw)); err == nil {
			t.Fatal("accepted missing/null required modified")
		}
	}
	for _, state := range []intel.TimestampState{intel.TimestampAbsent, intel.TimestampNull} {
		if got := advisoryProfileActivity(intel.OSVTimes{Modified: intel.OSVTimestamp{State: state}}, profileNow); got != "unknown" {
			t.Fatal(got)
		}
	}
}

func TestQualifyAdvisoryMultipleSourceSlots(t *testing.T) {
	for _, kind := range []string{"github-reviewed", "malware", "openssf"} {
		doc := profileDocument(kind)
		second := profileSlot(profileDocument(kind))
		second["package"].(map[string]any)["name"] = "another"
		if kind == "openssf" {
			db := second["database_specific"].(map[string]any)
			db["source"] = strings.Replace(db["source"].(string), "/left-pad/", "/another/", 1)
		}
		doc["affected"] = append(doc["affected"].([]any), second)
		for i := 0; i < 2; i++ {
			if q := qualifyProfileDocument(t, doc, i); q.Category == "unknown" || len(q.Gaps) != 0 {
				t.Fatal(kind, i, q)
			}
		}
		second["database_specific"].(map[string]any)["correction"] = true
		if q := qualifyProfileDocument(t, doc, 0); q.Category != "unknown" || !hasMatchingGap(q.Gaps, "correction-unsupported") {
			t.Fatal(kind, q)
		}
	}
}

func TestQualifyAdvisoryProjectionGuards(t *testing.T) {
	raw, _ := json.Marshal(profileDocument("github-reviewed"))
	for _, mutate := range []func(*intel.SnapshotOriginalEvidence){
		func(r *intel.SnapshotOriginalEvidence) { r.State = intel.SnapshotOriginalUnknown },
		func(r *intel.SnapshotOriginalEvidence) { r.Header.SourceSHA256[0] ^= 1 },
		func(r *intel.SnapshotOriginalEvidence) { r.Affected.SourceSHA256[0] ^= 1 },
		func(r *intel.SnapshotOriginalEvidence) { r.Times.SourceSHA256[0] ^= 1 },
		func(r *intel.SnapshotOriginalEvidence) { r.Header.Schema = intel.OSVHeaderSchemaUnsupported },
		func(r *intel.SnapshotOriginalEvidence) { r.Header.ID.Value = "GHSA-2234-fmw7-43wx" },
		func(r *intel.SnapshotOriginalEvidence) { r.Affected.Entries[0].Name.Value = "another" },
	} {
		r := profileEvidence(t, raw)
		mutate(&r)
		if q := qualifyAdvisory(r, 0, profileNow); q.Category != "unknown" {
			t.Fatal(q)
		}
	}
}

func TestQualifyAdvisoryMultipleSlotsCorrectionsAndBindings(t *testing.T) {
	doc := profileDocument("github-reviewed")
	second := profileSlot(profileDocument("github-reviewed"))
	second["package"].(map[string]any)["name"] = "another"
	second["versions"] = []string{"2.0.0"}
	doc["affected"] = append(doc["affected"].([]any), second)
	for slot := 0; slot < 2; slot++ {
		if got := qualifyProfileDocument(t, doc, slot); got.Category != "vulnerability" {
			t.Fatal(got)
		}
	}
	if got := qualifyProfileDocument(t, doc, 2); got.Category != "unknown" || !hasMatchingGap(got.Gaps, "binding-unqualified") {
		t.Fatal(got)
	}
	// A changed original has new digest and re-evaluated conditions, not an ID cache.
	for _, useRange := range []bool{false, true} {
		for _, corrected := range []bool{false, true} {
			d := profileDocument("github-reviewed")
			version := "1.0.0"
			if corrected {
				version = "2.0.0"
			}
			profileSlot(d)["versions"] = []string{version}
			if useRange {
				delete(profileSlot(d), "versions")
				profileSlot(d)["ranges"] = []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]any{"introduced": version}}}}
			}
			raw, _ := json.Marshal(d)
			r := profileEvidence(t, raw)
			if q := qualifyAdvisory(r, 0, profileNow); q.Category != "vulnerability" {
				t.Fatal(q)
			}
			query, _ := intel.ParseSemVer("1.0.0")
			v, err := intel.EvaluateOSVNPMVersionConditions(r.Header, r.Affected, query)
			want := intel.OSVVersionMatch
			if corrected {
				want = intel.OSVVersionNoMatch
			}
			if err != nil || v.Entries[0].Outcome != want {
				t.Fatal(v, err)
			}
		}
	}
	raw, _ := json.Marshal(doc)
	r := profileEvidence(t, raw)
	r.Raw = append(r.Raw, ' ')
	if got := qualifyAdvisory(r, 0, profileNow); got.Category != "unknown" {
		t.Fatal("accepted changed bytes", got)
	}
}
