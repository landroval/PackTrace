// Package inspect consumes bounded supplied metadata and exports a portable-only view.
package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"packtrace/internal/demo"
	"packtrace/internal/jsoninput"
)

type Result struct {
	Schema            string           `json:"schema"`
	Experimental      bool             `json:"experimental"`
	Scope             string           `json:"scope"`
	Privacy           string           `json:"privacy"`
	AdvisoryReference string           `json:"advisory_reference"`
	Inventory         []Observation    `json:"inventory"`
	Evaluations       []Evaluation     `json:"evaluations"`
	Candidates        []demo.Candidate `json:"candidates"`
	Findings          []string         `json:"findings"`
	Coverage          []demo.Coverage  `json:"coverage"`
	ExitCode          int              `json:"exit_code"`
}

type Observation struct {
	Reference            string `json:"reference"`
	Observation          string `json:"observation"`
	NameQualification    string `json:"name_qualification"`
	VersionQualification string `json:"version_qualification"`
	LinkQualification    string `json:"link_qualification"`
}

type Evaluation struct {
	PackageIndex          int            `json:"package_index"`
	AffectedIndex         int            `json:"affected_index"`
	IdentityComparison    string         `json:"identity_comparison"`
	IdentityQualification string         `json:"identity_qualification"`
	VersionOutcome        string         `json:"version_outcome"`
	VersionFullyEvaluated bool           `json:"version_fully_evaluated"`
	Withdrawal            string         `json:"withdrawal"`
	Support               []demo.Support `json:"support"`
	Problems              []demo.Problem `json:"problems"`
}

const maxWireBytes = 1_048_576

// Read never exports raw analysis, hashes or caller-selected diagnostic text.
func Read(in io.Reader) (Result, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if err != nil {
		return Result{}, errors.New("inspect: read-failed")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code != "" || len(fields) != 2 {
		return Result{}, errors.New("inspect: invalid-input")
	}
	lock, advisory := bytes.TrimSpace(fields["lockfile"]), bytes.TrimSpace(fields["advisory"])
	if len(lock) == 0 || lock[0] != '{' || len(advisory) == 0 || advisory[0] != '{' {
		return Result{}, errors.New("inspect: invalid-input")
	}
	raw, err := demo.EvaluateMetadata(lock, advisory)
	if err != nil {
		return Result{}, errors.New("inspect: invalid-metadata")
	}
	result := Result{Schema: "packtrace.inspect.v1", Experimental: true, Scope: "supplied-metadata", Privacy: "portable", AdvisoryReference: "advisory-0", Inventory: []Observation{}, Evaluations: []Evaluation{}, Candidates: raw.Candidates, Findings: raw.Findings, Coverage: raw.Coverage, ExitCode: raw.ExitCode}
	for i, o := range raw.Inventory {
		result.Inventory = append(result.Inventory, Observation{fmt.Sprintf("package-%d", i), o.Observation, o.NameQualification, o.VersionQualification, o.LinkQualification})
	}
	for _, e := range raw.Evaluations {
		comparison := "indeterminate"
		if raw.Inventory[e.PackageIndex].NameQualification == "value" && e.IdentityQualification == "candidate" {
			comparison = "different"
			if e.IdentityEqual {
				comparison = "equal"
			}
		}
		result.Evaluations = append(result.Evaluations, Evaluation{e.PackageIndex, e.AffectedIndex, comparison, e.IdentityQualification, e.VersionOutcome, e.VersionFullyEvaluated, e.Withdrawal, e.Support, e.Problems})
	}
	return result, nil
}

// Render accepts only the allowlisted portable result, not the raw analysis type.
func Render(r Result, format string) ([]byte, error) {
	if format == "json" {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return nil, errors.New("inspect: report-failed")
		}
		return append(data, '\n'), nil
	}
	if format != "terminal" {
		return nil, errors.New("inspect: invalid-format")
	}
	var text strings.Builder
	fmt.Fprintln(&text, "EXPERIMENTAL INSPECTION — supplied metadata; portable; not a target scan")
	fmt.Fprintf(&text, "Locked entries: %d\n", len(r.Inventory))
	for _, o := range r.Inventory {
		fmt.Fprintf(&text, "  %s [%s]: name=%s version=%s link=%s\n", o.Reference, o.Observation, o.NameQualification, o.VersionQualification, o.LinkQualification)
	}
	for _, e := range r.Evaluations {
		fmt.Fprintf(&text, "  package[%d] affected[%d]: identity=%s comparison=%s version=%s fully_evaluated=%t withdrawal=%s\n", e.PackageIndex, e.AffectedIndex, e.IdentityQualification, e.IdentityComparison, e.VersionOutcome, e.VersionFullyEvaluated, e.Withdrawal)
		for _, s := range e.Support {
			fmt.Fprintf(&text, "    support: version[%d] range[%d]\n", s.VersionIndex, s.RangeIndex)
		}
		for _, p := range e.Problems {
			fmt.Fprintf(&text, "    limitation: %s version[%d] range[%d] event[%d]\n", p.Kind, p.VersionIndex, p.RangeIndex, p.EventIndex)
		}
	}
	fmt.Fprintf(&text, "Candidates: %d (identity/version only; not enforcement eligible)\nConfirmed findings: %d\n", len(r.Candidates), len(r.Findings))
	for _, c := range r.Coverage {
		fmt.Fprintf(&text, "  %s: %s (%s)\n", c.Check, c.Outcome, c.Reason)
	}
	fmt.Fprintf(&text, "Required coverage: incomplete\nExit: %d\n", r.ExitCode)
	return []byte(text.String()), nil
}
