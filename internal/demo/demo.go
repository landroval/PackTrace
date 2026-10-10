// Package demo evaluates experimental metadata and incorporated inert scenarios.
// Its internal analysis contains raw claims; it is not a portable public report.
package demo

import (
	"errors"
	"fmt"

	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/inventory"
)

type Result struct {
	Schema          string        `json:"schema"`
	Experimental    bool          `json:"experimental"`
	Scenario        string        `json:"scenario"`
	Scope           string        `json:"scope"`
	Inputs          Inputs        `json:"inputs"`
	Inventory       []Observation `json:"inventory"`
	Evaluations     []Evaluation  `json:"evaluations"`
	Candidates      []Candidate   `json:"candidates"`
	Findings        []string      `json:"findings"`
	Coverage        []Coverage    `json:"coverage"`
	ExitCode        int           `json:"exit_code"`
	IdentityProfile string        `json:"-"`
}

type Inputs struct {
	LockSHA256     string `json:"lock_sha256"`
	AdvisorySHA256 string `json:"advisory_sha256"`
	AdvisoryID     string `json:"advisory_id"`
}

type Observation struct {
	Location              string `json:"location"`
	Name                  string `json:"name"`
	Version               string `json:"version"`
	Observation           string `json:"observation"`
	NameQualification     string `json:"-"`
	VersionQualification  string `json:"-"`
	LinkQualification     string `json:"-"`
	SelectedName          string `json:"-"`
	IdentitySource        string `json:"-"`
	IdentityQualification string `json:"-"`
}

type Evaluation struct {
	PackageIndex          int       `json:"package_index"`
	AffectedIndex         int       `json:"affected_index"`
	IdentityEqual         bool      `json:"identity_equal"`
	IdentityQualification string    `json:"identity_qualification"`
	VersionOutcome        string    `json:"version_outcome"`
	VersionFullyEvaluated bool      `json:"version_fully_evaluated"`
	Withdrawal            string    `json:"withdrawal"`
	Support               []Support `json:"support"`
	Problems              []Problem `json:"problems"`
}

type Support struct {
	VersionIndex int `json:"version_index"`
	RangeIndex   int `json:"range_index"`
}

type Problem struct {
	Kind         string `json:"kind"`
	VersionIndex int    `json:"version_index"`
	RangeIndex   int    `json:"range_index"`
	EventIndex   int    `json:"event_index"`
}

type Candidate struct {
	PackageIndex        int    `json:"package_index"`
	AffectedIndex       int    `json:"affected_index"`
	Kind                string `json:"kind"`
	EnforcementEligible bool   `json:"enforcement_eligible"`
}

type Coverage struct {
	Check   string `json:"check"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// EvaluateScenario retains its incorporated-input contract and original view.
func EvaluateScenario(name string) (Result, error) {
	lockBytes, advisoryBytes, err := scenarioInputs(name)
	if err != nil {
		return Result{}, err
	}
	result, err := EvaluateMetadata(lockBytes, advisoryBytes)
	if err != nil {
		return Result{}, err
	}
	result.Schema, result.Scope, result.Scenario = "packtrace.demo.v1", "owned-synthetic-fixture", name
	result.Coverage = result.Coverage[:5]
	result.Coverage[0] = Coverage{"fixture-inventory", "completed", "owned-fixture-only"}
	if result.Coverage[1].Outcome == "completed" {
		result.Coverage[1].Reason = "qualified-fixture-conditions"
	}
	return result, nil
}

// EvaluateMetadata retains explicit-name-only comparison by default.
func EvaluateMetadata(lockBytes, advisoryBytes []byte) (Result, error) {
	return EvaluateMetadataProfile(lockBytes, advisoryBytes, "explicit-only")
}

// EvaluateMetadataProfile selects an experimental interpretation, not producer
// proof. Raw analysis must pass through the inspect allowlist before export.
func EvaluateMetadataProfile(lockBytes, advisoryBytes []byte, profile string) (Result, error) {
	if profile != "explicit-only" && profile != "npm-lock-v2-v3" {
		return Result{}, errors.New("demo: invalid-profile")
	}
	lock, err := inventory.ParseNPMLock(lockBytes)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
	}
	if len(lock.Packages) > 64 {
		return Result{}, errors.New("demo: limit-exceeded")
	}
	locked, err := inventory.ProjectNPMLock(lock)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
	}
	var names inventory.NPMLockNames
	if profile == "npm-lock-v2-v3" {
		names, err = inventory.ProjectNPMLockNames(locked)
		if err != nil || names.SourceSHA256 != locked.SourceSHA256 || len(names.Entries) != len(locked.Records) {
			return Result{}, errors.New("demo: invalid-name-projection")
		}
	}
	advisory, err := intel.ParseOSVRecord(advisoryBytes)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}
	header, err := intel.ProjectOSVHeader(advisory)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}
	affected, err := intel.ProjectOSVAffected(advisory)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}
	if len(affected.Entries) > 64 {
		return Result{}, errors.New("demo: limit-exceeded")
	}
	identities, err := intel.QualifyOSVNPMIdentities(header, affected)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}
	times, err := intel.ProjectOSVTimes(advisory)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}

	result := Result{Schema: "packtrace.internal.metadata.v1", Experimental: true,
		Scope: "supplied-metadata", Inputs: Inputs{fmt.Sprintf("%x", locked.SourceSHA256), fmt.Sprintf("%x", header.SourceSHA256), header.ID.Value},
		Inventory: []Observation{}, Evaluations: []Evaluation{}, Candidates: []Candidate{}, Findings: []string{}}
	versionComplete := len(identities.Entries) > 0
	recordsComplete := true
	hypotheses := false
	if profile == "npm-lock-v2-v3" {
		result.IdentityProfile = profile
	}
	for recordIndex, record := range locked.Records {
		if record.Location == "" {
			continue
		} // Project root, not a dependency instance.
		nameState, versionState := fieldLabel(record.Name.State), fieldLabel(record.Version.State)
		if nameState == "value" && record.Name.Value == "" {
			nameState = "empty"
		}
		linkState := fieldLabel(record.Link.State)
		if record.Link.State == inventory.FieldValue {
			linkState = "non-link"
			if record.Link.Value {
				linkState = "link"
			}
		}
		query, queryErr := intel.ParseSemVer(record.Version.Value)
		queryOK := record.Version.State == inventory.FieldValue && queryErr == nil
		if record.Version.State == inventory.FieldValue {
			versionState = "qualified"
			if !queryOK {
				versionState = "invalid-semver"
			}
		}
		var conditions intel.OSVVersionConditions
		if queryOK {
			conditions, err = intel.EvaluateOSVVersionConditions(header, affected, query)
			if err != nil {
				return Result{}, errors.New("demo: invalid-version-conditions")
			}
			if len(conditions.Entries) != len(identities.Entries) {
				return Result{}, errors.New("demo: inconsistent-projections")
			}
		} else {
			versionComplete = false
		}
		selectedName, identitySource, identityQualification := record.Name.Value, "", ""
		nameOK := nameState == "value"
		if profile == "npm-lock-v2-v3" {
			selection := names.Entries[recordIndex]
			if selection.Index != recordIndex || selection.Location != record.Location || selection.DeclaredName != record.Name {
				return Result{}, errors.New("demo: inconsistent-name-projection")
			}
			selectedName, identitySource, identityQualification = selection.SelectedName, selection.Source, selection.Qualification
			nameOK = selectedName != ""
			hypotheses = hypotheses || identitySource == "locator-profile"
		}
		linkOK := linkState == "absent" || linkState == "non-link"
		recordsComplete = recordsComplete && nameState == "value" && queryOK && linkOK
		packageIndex := len(result.Inventory)
		result.Inventory = append(result.Inventory, Observation{Location: record.Location, Name: record.Name.Value, Version: record.Version.Value, Observation: "locked", NameQualification: nameState, VersionQualification: versionState, LinkQualification: linkState, SelectedName: selectedName, IdentitySource: identitySource, IdentityQualification: identityQualification})
		for i, identity := range identities.Entries {
			equal := nameOK && identity.Name.State == intel.OSVFieldValue && identity.Name.Value == selectedName
			e := Evaluation{PackageIndex: packageIndex, AffectedIndex: identity.Index, IdentityEqual: equal,
				IdentityQualification: identityLabel(identity.Qualification), VersionOutcome: "not-evaluated",
				Withdrawal: withdrawalLabel(times.Withdrawal), Support: []Support{}, Problems: []Problem{}}
			if !queryOK {
				result.Evaluations = append(result.Evaluations, e)
				continue
			}
			condition := conditions.Entries[i]
			e.VersionOutcome, e.VersionFullyEvaluated = versionLabel(condition.Outcome), condition.FullyEvaluated
			for _, support := range condition.Support {
				e.Support = append(e.Support, Support{support.VersionIndex, support.RangeIndex})
			}
			for _, problem := range condition.Problems {
				e.Problems = append(e.Problems, Problem{string(problem.Kind), problem.VersionIndex, problem.RangeIndex, problem.EventIndex})
			}
			result.Evaluations = append(result.Evaluations, e)
			versionComplete = versionComplete && condition.FullyEvaluated
			if equal && linkOK && identity.Qualification == intel.OSVNPMIdentityCandidate && condition.Outcome == intel.OSVVersionMatch && times.Withdrawal == intel.WithdrawalNotDeclared {
				kind := "identity-version-only"
				if identitySource == "locator-profile" {
					kind = "installation-name-version-only"
				}
				result.Candidates = append(result.Candidates, Candidate{packageIndex, identity.Index, kind, false})
			}
		}
	}
	versionComplete = versionComplete && len(result.Inventory) > 0
	versionState, versionReason := "completed", "qualified-supplied-conditions"
	if !versionComplete {
		versionState, versionReason = "incomplete", "unsupported-or-unqualified"
	}
	result.Coverage = []Coverage{
		{"supplied-inventory", "completed", "supplied-document-only"},
		{"version-conditions", versionState, versionReason},
		{"advisory-applicability", "incomplete", "origin-freshness-category-unqualified"},
		{"installed-inventory", "not-run", "no-target-access"},
		{"integrity", "not-run", "no-target-access"},
	}
	recordState, recordReason := "completed", "explicit-inspectable-claims"
	if !recordsComplete || len(result.Inventory) == 0 {
		recordState, recordReason = "incomplete", "missing-unqualified-or-link-claims"
	}
	result.Coverage = append(result.Coverage, Coverage{"record-qualification", recordState, recordReason})
	if hypotheses {
		result.Coverage = append(result.Coverage, Coverage{"canonical-name-correspondence", "incomplete", "installation-name-hypothesis"})
	}
	result.ExitCode = cli.SelectScanExit(cli.ScanExitConditions{RequiredCoverageIncomplete: true})
	return result, nil
}

func fieldLabel(state inventory.FieldState) string {
	switch state {
	case inventory.FieldAbsent:
		return "absent"
	case inventory.FieldNull:
		return "null"
	case inventory.FieldValue:
		return "value"
	default:
		return "invalid-type"
	}
}

func identityLabel(q intel.OSVNPMIdentityQualification) string {
	switch q {
	case intel.OSVNPMIdentityCandidate:
		return "candidate"
	case intel.OSVNPMIdentityUnqualified:
		return "unqualified"
	case intel.OSVNPMIdentityConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

func versionLabel(q intel.OSVVersionOutcome) string {
	switch q {
	case intel.OSVVersionMatch:
		return "match"
	case intel.OSVVersionNoMatch:
		return "no-match"
	default:
		return "indeterminate"
	}
}

func withdrawalLabel(q intel.WithdrawalState) string {
	switch q {
	case intel.WithdrawalNotDeclared:
		return "not-declared"
	case intel.WithdrawalReported:
		return "reported"
	default:
		return "unknown"
	}
}

func scenarioInputs(name string) ([]byte, []byte, error) {
	version := "1.2.3"
	entry := `{"package":{"ecosystem":"npm","name":"demo-package"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}`
	withdrawal := ""
	switch name {
	case "candidate":
	case "no-version-match":
		version = "2.0.0"
	case "unsupported":
		entry = `{"package":{"ecosystem":"npm","name":"demo-package"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}`
	case "withdrawn":
		withdrawal = `,"withdrawn":"2026-01-02T00:00:00Z"`
	case "different-identity":
		entry = `{"package":{"ecosystem":"npm","name":"other-package"},"versions":["1.2.3"]},{"package":{"ecosystem":"npm","name":"demo-package"},"versions":["9.9.9"]}`
	case "malformed":
	default:
		return nil, nil, errors.New("demo: unknown-scenario")
	}
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/demo-package":{"name":"demo-package","version":"` + version + `"}}}`
	advisory := `{"id":"DEMO-OSV-001","modified":"2026-01-01T00:00:00Z"` + withdrawal + `,"affected":[` + entry + `]}`
	if name == "malformed" {
		advisory = `{"id":"DEMO-OSV-001","id":"PRIVATE-MALFORMED-MARKER","modified":"2026-01-01T00:00:00Z"}`
	}
	return []byte(lock), []byte(advisory), nil
}
