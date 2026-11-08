package inventory

import "testing"

func TestNPM12IgnoresShrinkwrap(t *testing.T) {
	for _, profile := range []string{"npm@12.x", "npm@12.0.0", "npm@12.2.2", "npm@12.99.0"} {
		for _, tt := range []struct {
			name         string
			shrink, lock NPMInputState
			candidate    NPMInputCandidate
			state        NPMInputSelectionState
		}{
			{"both-present", NPMInputState{2, 1}, NPMInputState{2, 1}, NPMInputCandidatePackageLock, NPMInputSelectionUsable},
			{"unsafe-shrinkwrap", NPMInputState{0, 3}, NPMInputState{2, 1}, NPMInputCandidatePackageLock, NPMInputSelectionUsable},
			{"shrinkwrap-only", NPMInputState{2, 1}, NPMInputState{1, 0}, NPMInputCandidateNone, NPMInputSelectionAbsent},
			{"unknown-package-lock", NPMInputState{2, 1}, NPMInputState{0, 2}, NPMInputCandidateNone, NPMInputSelectionIndeterminate},
			{"bad-package-lock", NPMInputState{2, 1}, NPMInputState{2, 5}, NPMInputCandidatePackageLock, NPMInputSelectionUnusable},
		} {
			t.Run(profile+"/"+tt.name, func(t *testing.T) {
				got, err := SelectNPMInput(profile, tt.shrink, tt.lock)
				if err != nil || !got.ProfileQualified || got.Candidate != tt.candidate || got.State != tt.state || got.Shrinkwrap != tt.shrink || got.PackageLock != tt.lock {
					t.Fatalf("npm12 precedence or retained evidence lost: %+v %v", got, err)
				}
			})
		}
	}
}
