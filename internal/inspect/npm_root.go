package inspect

import (
	"bytes"
	"errors"
	"io"

	"packtrace/internal/inventory"
	"packtrace/internal/jsoninput"
)

// NPMRootResult is the same portable count-only shape as Bun's root result.
type NPMRootResult = BunRootResult
type NPMRootGroup = BunRootGroup
type NPMRootCounts = BunRootCounts

// ReadNPMRoot compares supplied manifest and npm lockfile objects, without target access.
func ReadNPMRoot(in io.Reader) (NPMRootResult, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if err != nil {
		return NPMRootResult{}, npmRootError("read-failed")
	}
	if len(data) > maxWireBytes {
		return NPMRootResult{}, npmRootError("limit-exceeded")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code == "limit-exceeded" {
		return NPMRootResult{}, npmRootError(code)
	}
	if code != "" || len(fields) != 2 {
		return NPMRootResult{}, npmRootError("invalid-input")
	}
	manifestRaw, lockRaw := bytes.TrimSpace(fields["manifest"]), bytes.TrimSpace(fields["lockfile"])
	if len(manifestRaw) == 0 || manifestRaw[0] != '{' || len(lockRaw) == 0 || lockRaw[0] != '{' {
		return NPMRootResult{}, npmRootError("invalid-input")
	}
	md, err := inventory.ParseManifest(manifestRaw)
	if err != nil {
		return NPMRootResult{}, npmRootMetadataError(err)
	}
	manifest, err := inventory.ProjectManifest(md)
	if err != nil {
		return NPMRootResult{}, npmRootMetadataError(err)
	}
	ld, err := inventory.ParseNPMLock(lockRaw)
	if err != nil {
		return NPMRootResult{}, npmRootMetadataError(err)
	}
	lock, err := inventory.ProjectNPMLock(ld)
	if err != nil {
		return NPMRootResult{}, npmRootMetadataError(err)
	}
	comparison, err := inventory.CompareRootRequirements(manifest, lock)
	if err != nil {
		return NPMRootResult{}, npmRootMetadataError(err)
	}
	result := NPMRootResult{
		Schema: "packtrace.compare.npm-root.v1", Experimental: true,
		Scope: "supplied-root-metadata", Privacy: "portable",
		RootPresent: comparison.RootPresent, ComparisonComplete: comparison.Complete,
		Groups: []NPMRootGroup{}, ExitCode: 3,
		Limitations: []string{"textual-comparison-only", "counts-exclude-uninspectable-groups", "no-installed-or-security-assessment"},
	}
	for _, source := range comparison.Groups {
		group := NPMRootGroup{Name: source.Name, ManifestState: bunRootState(source.ManifestState), LockState: bunRootState(source.LockState), ComparisonComplete: source.Complete}
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
				return NPMRootResult{}, npmRootError("invalid-metadata")
			}
		}
		result.Groups = append(result.Groups, group)
	}
	return result, nil
}

// RenderNPMRoot renders only the portable count-only model.
func RenderNPMRoot(r NPMRootResult, format string) ([]byte, error) {
	data, err := RenderBunRoot(r, format)
	if err != nil {
		if format != "terminal" && format != "json" {
			return nil, npmRootError("invalid-format")
		}
		return nil, npmRootError("report-failed")
	}
	return data, nil
}

func npmRootMetadataError(err error) error {
	var parse *inventory.ParseError
	if errors.As(err, &parse) && parse.Code == "limit-exceeded" {
		return npmRootError("limit-exceeded")
	}
	return npmRootError("invalid-metadata")
}
func npmRootError(code string) error { return errors.New("compare-npm-root: " + code) }
