package managerprofile

import "testing"

func TestStableManagerRanges(t *testing.T) {
	for _, profile := range []string{"npm@7.0.0", "npm@7.24.2", "npm@8.0.0", "npm@8.19.4", "npm@9.9.4", "npm@10.9.9", "npm@11.20.0", "npm@12.2.2", "npm@7-11", "npm@10-11", "npm@12.x"} {
		if !SupportsNPM(profile) {
			t.Errorf("npm refused %s", profile)
		}
	}
	for _, profile := range []string{"npm@6.14.18", "npm@13.0.0", "npm@7", "npm@07.24.2", "npm@7.024.2", "npm@9.9.4-beta.1", "npm@9.9.4+hash", "npm@7.x", "npm@7.24.2 ", "npm@7.999999999999999.0"} {
		if SupportsNPM(profile) {
			t.Errorf("npm admitted %s", profile)
		}
	}
	for _, profile := range []string{"bun@1.2.0", "bun@1.2.23", "bun@1.3.0", "bun@1.3.14", "bun@1.4.0", "bun@1.4.2", "bun@1.4.3", "bun@1.2.x", "bun@1.3.x", "bun@1.4.x", "bun@1.2-1.4"} {
		if !SupportsBun(profile) {
			t.Errorf("Bun refused %s", profile)
		}
	}
	for _, profile := range []string{"bun@1.1.39", "bun@1.5.0", "bun@2.0.0", "bun@01.2.23", "bun@1.02.23", "bun@1.2.023", "bun@1.2.23-beta.1", "bun@1.4.2+hash", "bun@1.2", "bun@1.2.23 ", "bun@1.2.999999999999999"} {
		if SupportsBun(profile) {
			t.Errorf("Bun admitted %s", profile)
		}
	}
}
