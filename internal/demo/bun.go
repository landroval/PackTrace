package demo

import (
	"errors"
	"packtrace/internal/inventory"
)

// EvaluateBunMetadata retains original text/tuple evidence. A recognized npm
// tuple remains a recorded claim, not authenticated origin or an installed node.
func EvaluateBunMetadata(lockBytes, advisoryBytes []byte) (Result, error) {
	lock, err := inventory.ParseBunLock(lockBytes)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
	}
	if len(lock.Packages) > 64 || len(lock.Workspaces) > 64 {
		return Result{}, errors.New("demo: limit-exceeded")
	}
	projected, err := inventory.ProjectBunLock(lock)
	if err != nil {
		return Result{}, errors.New("demo: invalid-lockfile")
	}
	observations := []Observation{}
	for i, record := range projected.Records {
		if record.Kind == inventory.BunKindRoot {
			continue
		}
		o := Observation{SourceIndex: i, ResolutionQualification: fieldLabel(record.Resolution.State), TupleKind: bunKindLabel(record.Kind), Location: record.Key, Name: record.Name.Value, Version: record.Resolution.Value, Observation: "locked", NameQualification: fieldLabel(record.Name.State), VersionQualification: "not-version", LinkQualification: "unsupported-source", IdentitySource: "bun-tuple", IdentityQualification: "unqualified-tuple"}
		if o.NameQualification == "value" && o.Name == "" {
			o.NameQualification = "empty"
		}
		if record.Kind == inventory.BunKindNPM {
			o.VersionQualification = fieldLabel(record.Resolution.State)
			o.LinkQualification = "non-link"
			o.IdentityQualification = "tuple-claim"
			if o.NameQualification == "value" {
				o.SelectedName = record.Name.Value
			}
		}
		observations = append(observations, o)
	}
	return evaluateObservations(projected.SourceSHA256, observations, advisoryBytes, "bun-npm-tuples")
}

func bunKindLabel(kind inventory.BunResolutionKind) string {
	switch kind {
	case inventory.BunKindNPM:
		return "npm"
	case inventory.BunKindGit:
		return "git"
	case inventory.BunKindGitHub:
		return "github"
	case inventory.BunKindTarball:
		return "tarball"
	case inventory.BunKindFolder:
		return "folder"
	case inventory.BunKindLink:
		return "link"
	case inventory.BunKindWorkspace:
		return "workspace"
	case inventory.BunKindRoot:
		return "root"
	default:
		return "unknown"
	}
}
