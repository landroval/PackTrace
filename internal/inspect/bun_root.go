package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"packtrace/internal/inventory"
	"packtrace/internal/jsoninput"
)

// BunRootResult contains only counts and fixed labels, never raw declarations.
// ComparisonComplete describes textual comparison, not investigation coverage.
type BunRootResult struct {
	Schema             string         `json:"schema"`
	Experimental       bool           `json:"experimental"`
	Scope              string         `json:"scope"`
	Privacy            string         `json:"privacy"`
	RootPresent        bool           `json:"root_present"`
	ComparisonComplete bool           `json:"comparison_complete"`
	Groups             []BunRootGroup `json:"groups"`
	Limitations        []string       `json:"limitations"`
	ExitCode           int            `json:"exit_code"`
}

type BunRootGroup struct {
	Name               string        `json:"name"`
	ManifestState      string        `json:"manifest_state"`
	LockState          string        `json:"lock_state"`
	ComparisonComplete bool          `json:"comparison_complete"`
	Counts             BunRootCounts `json:"counts"`
}

type BunRootCounts struct {
	Equal         int `json:"equal"`
	ManifestOnly  int `json:"manifest_only"`
	LockOnly      int `json:"lock_only"`
	TextChanged   int `json:"text_changed"`
	Indeterminate int `json:"indeterminate"`
}

// ReadBunRoot compares supplied root declarations without filesystem access.
func ReadBunRoot(in io.Reader) (BunRootResult, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if err != nil {
		return BunRootResult{}, bunRootError("read-failed")
	}
	if len(data) > maxWireBytes {
		return BunRootResult{}, bunRootError("limit-exceeded")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code == "limit-exceeded" {
		return BunRootResult{}, bunRootError(code)
	}
	if code != "" || len(fields) != 2 {
		return BunRootResult{}, bunRootError("invalid-input")
	}
	manifestRaw := bytes.TrimSpace(fields["manifest"])
	var text string
	if len(manifestRaw) == 0 || manifestRaw[0] != '{' || json.Unmarshal(fields["lockfile_text"], &text) != nil || text == "" {
		return BunRootResult{}, bunRootError("invalid-input")
	}
	md, err := inventory.ParseManifest(manifestRaw)
	if err != nil {
		return BunRootResult{}, bunRootMetadataError(err)
	}
	manifest, err := inventory.ProjectManifest(md)
	if err != nil {
		return BunRootResult{}, bunRootMetadataError(err)
	}
	ld, err := inventory.ParseBunLock([]byte(text))
	if err != nil {
		return BunRootResult{}, bunRootMetadataError(err)
	}
	lock, err := inventory.ProjectBunWorkspaces(ld)
	if err != nil {
		return BunRootResult{}, bunRootMetadataError(err)
	}
	comparison, err := inventory.CompareBunRootRequirements(manifest, lock)
	if err != nil {
		return BunRootResult{}, bunRootMetadataError(err)
	}
	result := BunRootResult{
		Schema: "packtrace.compare.bun-root.v1", Experimental: true,
		Scope: "supplied-root-metadata", Privacy: "portable",
		RootPresent: comparison.RootPresent, ComparisonComplete: comparison.Complete,
		Groups: []BunRootGroup{}, ExitCode: 3,
		Limitations: []string{"textual-comparison-only", "counts-exclude-uninspectable-groups", "no-installed-or-security-assessment"},
	}
	for _, source := range comparison.Groups {
		// The existing comparator validates fixed group names and omits rows
		// from uninspectable groups. Never export its raw names or requirements.
		group := BunRootGroup{Name: source.Name, ManifestState: bunRootState(source.ManifestState), LockState: bunRootState(source.LockState), ComparisonComplete: source.Complete}
		for _, entry := range source.Entries {
			switch entry.Outcome {
			case inventory.RequirementEqual:
				group.Counts.Equal++
			case inventory.RequirementManifestOnly:
				group.Counts.ManifestOnly++
			case inventory.RequirementLockOnly:
				group.Counts.LockOnly++
			case inventory.RequirementTextChanged:
				group.Counts.TextChanged++
			case inventory.RequirementIndeterminate:
				group.Counts.Indeterminate++
			default:
				return BunRootResult{}, bunRootError("invalid-metadata")
			}
		}
		result.Groups = append(result.Groups, group)
	}
	return result, nil
}

// RenderBunRoot renders the adapter-owned portable model, not raw projections.
func RenderBunRoot(r BunRootResult, format string) ([]byte, error) {
	if format == "json" {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return nil, bunRootError("report-failed")
		}
		return append(data, '\n'), nil
	}
	if format != "terminal" {
		return nil, bunRootError("invalid-format")
	}
	var text strings.Builder
	fmt.Fprintln(&text, "EXPERIMENTAL ROOT COMPARISON — supplied metadata; portable; not a target scan")
	fmt.Fprintf(&text, "Root present: %t\nTextual comparison complete: %t\n", r.RootPresent, r.ComparisonComplete)
	for _, g := range r.Groups {
		fmt.Fprintf(&text, "%s: manifest=%s lock=%s textual-complete=%t equal=%d manifest-only=%d lock-only=%d text-changed=%d indeterminate=%d\n", g.Name, g.ManifestState, g.LockState, g.ComparisonComplete, g.Counts.Equal, g.Counts.ManifestOnly, g.Counts.LockOnly, g.Counts.TextChanged, g.Counts.Indeterminate)
	}
	fmt.Fprintln(&text, "Textual comparison is not scan coverage.")
	for _, limitation := range r.Limitations {
		fmt.Fprintf(&text, "  limitation: %s\n", limitation)
	}
	fmt.Fprintf(&text, "Exit: %d\n", r.ExitCode)
	return []byte(text.String()), nil
}

func bunRootState(state inventory.FieldState) string {
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

func bunRootMetadataError(err error) error {
	var parse *inventory.ParseError
	if errors.As(err, &parse) && parse.Code == "limit-exceeded" {
		return bunRootError("limit-exceeded")
	}
	return bunRootError("invalid-metadata")
}

func bunRootError(code string) error { return errors.New("compare-bun-root: " + code) }
