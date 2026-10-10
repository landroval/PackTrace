package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"packtrace/internal/demo"
	"packtrace/internal/intel"
	"packtrace/internal/inventory"
	"packtrace/internal/jsoninput"
)

type BatchResult struct {
	Schema          string          `json:"schema"`
	Experimental    bool            `json:"experimental"`
	Scope           string          `json:"scope"`
	Privacy         string          `json:"privacy"`
	IdentityProfile string          `json:"identity_profile,omitempty"`
	LockedEntries   int             `json:"locked_entries"`
	Advisories      []BatchAdvisory `json:"advisories"`
	CandidateCount  int             `json:"candidate_count"`
	Findings        []string        `json:"findings"`
	Coverage        []demo.Coverage `json:"coverage"`
	ExitCode        int             `json:"exit_code"`
}

type BatchAdvisory struct {
	Reference string  `json:"reference"`
	State     string  `json:"state"`
	Report    *Result `json:"report,omitempty"`
}

func ReadBatch(in io.Reader) (BatchResult, error) { return ReadBatchProfile(in, "explicit-only") }

// ReadBatchProfile preflights the whole supplied scope before repeated evaluation.
// Malformed whole-wire JSON and budget failures are fatal, not record-local gaps.
func ReadBatchProfile(in io.Reader, profile string) (BatchResult, error) {
	if profile != "explicit-only" && profile != "npm-lock-v2-v3" {
		return BatchResult{}, errors.New("inspect-batch: invalid-profile")
	}
	data, e := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if e != nil {
		return BatchResult{}, errors.New("inspect-batch: read-failed")
	}
	if len(data) > maxWireBytes {
		return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code != "" || len(fields) != 2 {
		return BatchResult{}, errors.New("inspect-batch: invalid-input")
	}
	lock := bytes.TrimSpace(fields["lockfile"])
	var ads []json.RawMessage
	if len(lock) == 0 || lock[0] != '{' || json.Unmarshal(fields["advisories"], &ads) != nil || len(ads) == 0 {
		return BatchResult{}, errors.New("inspect-batch: invalid-input")
	}
	if len(ads) > 16 {
		return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
	}
	locked, e := inventory.ParseNPMLock(lock)
	if e != nil {
		return BatchResult{}, errors.New("inspect-batch: invalid-lockfile")
	}
	if len(locked.Packages) > 64 {
		return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
	}
	projected, e := inventory.ProjectNPMLock(locked)
	if e != nil {
		return BatchResult{}, errors.New("inspect-batch: invalid-lockfile")
	}
	if profile == "npm-lock-v2-v3" {
		if _, e := inventory.ProjectNPMLockNames(projected); e != nil {
			return BatchResult{}, errors.New("inspect-batch: invalid-lockfile")
		}
	}
	count := 0
	for _, r := range projected.Records {
		if r.Location != "" {
			count++
		}
	}
	usable := make([]bool, len(ads))
	remaining := 64
	for i, raw := range ads {
		// Count raw affected positions even when id/modified or a member is unusable.
		var record map[string]json.RawMessage
		if json.Unmarshal(raw, &record) == nil && record != nil {
			var units []json.RawMessage
			if json.Unmarshal(record["affected"], &units) == nil {
				if len(units) > remaining {
					return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
				}
				remaining -= len(units)
			}
		}
		doc, e := intel.ParseOSVRecord(raw)
		if e != nil {
			continue
		}
		// Reuse the upstream nested versions/ranges/events budget, including records
		// whose version query or header profile will later abstain from evaluation.
		if _, e = intel.ProjectOSVAffected(doc); e != nil {
			var parse *intel.ParseError
			if errors.As(e, &parse) && parse.Code == "limit-exceeded" {
				return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
			}
			continue
		}
		usable[i] = true
	}
	if count*(64-remaining) > 4096 {
		return BatchResult{}, errors.New("inspect-batch: limit-exceeded")
	}
	result := BatchResult{Schema: "packtrace.inspect.batch.v1", Experimental: true, Scope: "supplied-metadata", Privacy: "portable", LockedEntries: count, Advisories: []BatchAdvisory{}, Findings: []string{}, ExitCode: 3, Coverage: []demo.Coverage{
		{Check: "advisory-records", Outcome: "completed", Reason: "supplied-records-only"},
		{Check: "advisory-applicability", Outcome: "incomplete", Reason: "origin-freshness-category-unqualified"},
		{Check: "installed-inventory", Outcome: "not-run", Reason: "no-target-access"},
		{Check: "integrity", Outcome: "not-run", Reason: "no-target-access"},
	}}
	if profile == "npm-lock-v2-v3" {
		result.IdentityProfile = profile
	}
	for i, raw := range ads {
		entry := BatchAdvisory{Reference: fmt.Sprintf("advisory-%d", i), State: "invalid-advisory"}
		if usable[i] {
			// ponytail: at most 16 bounded re-parses; share an evaluation context only
			// if measured batch cost justifies changing the existing single-record API.
			packet := append([]byte(`{"lockfile":`), lock...)
			packet = append(packet, []byte(`,"advisory":`)...)
			packet = append(packet, raw...)
			packet = append(packet, '}')
			report, e := ReadProfile(bytes.NewReader(packet), profile)
			if e == nil {
				report.AdvisoryReference = entry.Reference
				entry.State = "usable"
				entry.Report = &report
				result.CandidateCount += len(report.Candidates)
			}
		}
		if entry.Report == nil {
			result.Coverage[0].Outcome = "incomplete"
			result.Coverage[0].Reason = "one-or-more-records-unusable"
		}
		result.Advisories = append(result.Advisories, entry)
	}
	return result, nil
}

func RenderBatch(r BatchResult, format string) ([]byte, error) {
	if format == "json" {
		data, e := json.MarshalIndent(r, "", "  ")
		if e != nil {
			return nil, errors.New("inspect-batch: report-failed")
		}
		return append(data, '\n'), nil
	}
	if format != "terminal" {
		return nil, errors.New("inspect-batch: invalid-format")
	}
	var text strings.Builder
	fmt.Fprintln(&text, "EXPERIMENTAL BATCH INSPECTION — supplied metadata; portable; not a target scan")
	if r.IdentityProfile != "" {
		fmt.Fprintf(&text, "Identity profile: %s (interpretation only)\n", r.IdentityProfile)
	}
	fmt.Fprintf(&text, "Locked entries: %d\nAdvisory records: %d\n", r.LockedEntries, len(r.Advisories))
	for _, entry := range r.Advisories {
		fmt.Fprintf(&text, "%s: %s\n", entry.Reference, entry.State)
		if entry.Report != nil {
			data, e := Render(*entry.Report, "terminal")
			if e != nil {
				return nil, errors.New("inspect-batch: report-failed")
			}
			text.Write(data)
		}
	}
	fmt.Fprintf(&text, "Candidate comparisons: %d (not unique authenticated findings; not enforcement eligible)\nConfirmed findings: %d\n", r.CandidateCount, len(r.Findings))
	for _, c := range r.Coverage {
		fmt.Fprintf(&text, "  %s: %s (%s)\n", c.Check, c.Outcome, c.Reason)
	}
	fmt.Fprintf(&text, "Required coverage: incomplete\nExit: %d\n", r.ExitCode)
	return []byte(text.String()), nil
}
