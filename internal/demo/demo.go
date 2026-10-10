// Package demo connects real evidence readers with owned inert inputs only.
// Its experimental result is not a production scan report or qualification.
package demo

import (
	"errors"
	"fmt"

	"packtrace/internal/cli"
	"packtrace/internal/intel"
	"packtrace/internal/inventory"
)

type Result struct {
	Schema       string        `json:"schema"`
	Experimental bool          `json:"experimental"`
	Scenario     string        `json:"scenario"`
	Scope        string        `json:"scope"`
	Inputs       Inputs        `json:"inputs"`
	Inventory    []Observation `json:"inventory"`
	Evaluations  []Evaluation  `json:"evaluations"`
	Candidates   []Candidate   `json:"candidates"`
	Findings     []string      `json:"findings"`
	Coverage     []Coverage    `json:"coverage"`
	ExitCode     int           `json:"exit_code"`
}

type Inputs struct {
	LockSHA256     string `json:"lock_sha256"`
	AdvisorySHA256 string `json:"advisory_sha256"`
	AdvisoryID     string `json:"advisory_id"`
}

type Observation struct {
	Location    string `json:"location"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Observation string `json:"observation"`
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

// EvaluateScenario parses and derives a fresh result from incorporated inert
// fixtures. It accepts scenario names, never target paths or caller data.
func EvaluateScenario(name string) (Result, error) {
	lockBytes, advisoryBytes, err := scenarioInputs(name)
	if err != nil {
		return Result{}, err
	}
	lock, err := inventory.ParseNPMLock(lockBytes)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
	}
	locked, err := inventory.ProjectNPMLock(lock)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
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
	identities, err := intel.QualifyOSVNPMIdentities(header, affected)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}
	times, err := intel.ProjectOSVTimes(advisory)
	if err != nil {
		return Result{}, errors.New("demo: invalid-advisory")
	}

	result := Result{Schema: "packtrace.demo.v1", Experimental: true, Scenario: name,
		Scope: "owned-synthetic-fixture", Inputs: Inputs{fmt.Sprintf("%x", locked.SourceSHA256), fmt.Sprintf("%x", header.SourceSHA256), header.ID.Value},
		Inventory: []Observation{}, Evaluations: []Evaluation{}, Candidates: []Candidate{}, Findings: []string{}}
	versionComplete := true
	for _, record := range locked.Records {
		if record.Location == "" {
			continue
		} // Project root, not a dependency instance.
		if record.Name.State != inventory.FieldValue || record.Name.Value == "" || record.Version.State != inventory.FieldValue {
			return Result{}, errors.New("demo: unqualified-locked-record")
		}
		query, err := intel.ParseSemVer(record.Version.Value)
		if err != nil {
			return Result{}, errors.New("demo: unqualified-locked-version")
		}
		conditions, err := intel.EvaluateOSVVersionConditions(header, affected, query)
		if err != nil {
			return Result{}, errors.New("demo: invalid-version-conditions")
		}
		// All projections are from the same unchanged successful owned document.
		if len(conditions.Entries) != len(identities.Entries) {
			return Result{}, errors.New("demo: inconsistent-projections")
		}
		packageIndex := len(result.Inventory)
		result.Inventory = append(result.Inventory, Observation{record.Location, record.Name.Value, record.Version.Value, "locked"})
		for i, identity := range identities.Entries {
			condition := conditions.Entries[i]
			equal := identity.Name.State == intel.OSVFieldValue && identity.Name.Value == record.Name.Value
			e := Evaluation{PackageIndex: packageIndex, AffectedIndex: identity.Index, IdentityEqual: equal,
				IdentityQualification: identityLabel(identity.Qualification), VersionOutcome: versionLabel(condition.Outcome),
				VersionFullyEvaluated: condition.FullyEvaluated, Withdrawal: withdrawalLabel(times.Withdrawal), Support: []Support{}, Problems: []Problem{}}
			for _, support := range condition.Support {
				e.Support = append(e.Support, Support{support.VersionIndex, support.RangeIndex})
			}
			for _, problem := range condition.Problems {
				e.Problems = append(e.Problems, Problem{string(problem.Kind), problem.VersionIndex, problem.RangeIndex, problem.EventIndex})
			}
			result.Evaluations = append(result.Evaluations, e)
			versionComplete = versionComplete && condition.FullyEvaluated
			if equal && identity.Qualification == intel.OSVNPMIdentityCandidate && condition.Outcome == intel.OSVVersionMatch && times.Withdrawal == intel.WithdrawalNotDeclared {
				result.Candidates = append(result.Candidates, Candidate{packageIndex, identity.Index, "identity-version-only", false})
			}
		}
	}
	versionState, versionReason := "completed", "qualified-fixture-conditions"
	if !versionComplete {
		versionState, versionReason = "incomplete", "unsupported-or-unqualified"
	}
	result.Coverage = []Coverage{
		{"fixture-inventory", "completed", "owned-fixture-only"},
		{"version-conditions", versionState, versionReason},
		{"advisory-applicability", "incomplete", "origin-freshness-category-unqualified"},
		{"installed-inventory", "not-run", "no-target-access"},
		{"integrity", "not-run", "no-target-access"},
	}
	result.ExitCode = cli.SelectScanExit(cli.ScanExitConditions{RequiredCoverageIncomplete: true})
	return result, nil
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
