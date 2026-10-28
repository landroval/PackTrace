package inventory

// CompareBunRootRequirements applies the CompareRootRequirements rules to the Bun
// root workspace "". Other workspaces are never substitutes. The same caller
// pairing, unauthenticated digest and non-coverage limits apply.
func CompareBunRootRequirements(manifest ManifestProjection, lock BunWorkspaceProjection) (RootComparison, error) {
	if err := checkComparisonGroups(manifest.Groups, maxManifestDeclarations); err != nil {
		return RootComparison{}, err
	}
	if lock.Records == nil {
		return RootComparison{}, &ParseError{Code: "invalid-shape"}
	}
	result := RootComparison{ManifestSHA256: manifest.SourceSHA256, LockSHA256: lock.SourceSHA256}
	if len(lock.Records) == 0 || lock.Records[0].Location != "" {
		return result, nil
	}
	return compareRootGroups(manifest.Groups, lock.Records[0].Requirements, result)
}
