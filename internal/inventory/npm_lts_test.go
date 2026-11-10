package inventory

import "testing"

func TestNPMLTSProfiles(t *testing.T) {
	for _, profile := range []string{"npm@7-11", "npm@7.24.2", "npm@8.0.0", "npm@9.9.9", "npm@10-11", "npm@10.0.0", "npm@10.9.9", "npm@11.0.0", "npm@11.19.1", "npm@11.20.0", "npm@11.999.99", "npm@8.19.4"} {
		t.Run(profile, func(t *testing.T) {
			got, err := SelectNPMInput(profile, NPMInputState{Presence: NPMInputPresenceAbsent}, NPMInputState{Presence: NPMInputPresencePresent, Usability: NPMInputUsabilityUsable})
			if err != nil || !got.ProfileQualified || got.State != NPMInputSelectionUsable || got.Profile != profile {
				t.Fatalf("stable compatible interpretation refused: %+v, %v", got, err)
			}
		})
	}
	for _, profile := range []string{"npm@6.14.18", "npm@13.2.2", "npm@010.0.0", "npm@10.00.0", "npm@11.2.03", "npm@11.20", "npm@11.20.0-rc.1", "npm@11.20.0+build", "npm@11.4294967296.0", "npm@11.20.0\n", "npm@11.+1.0"} {
		got, err := SelectNPMInput(profile, NPMInputState{}, NPMInputState{})
		if err != nil || got.ProfileQualified {
			t.Fatalf("unsupported interpretation qualified: %q, %+v, %v", profile, got, err)
		}
	}
}
