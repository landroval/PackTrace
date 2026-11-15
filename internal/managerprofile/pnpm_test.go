package managerprofile

import "testing"

func TestPNPMFormatAndProducerHintsRemainSeparate(t *testing.T) {
	for _, hint := range []string{"pnpm@9.15.9", "pnpm@10.34.9", "pnpm@9.0.0", "pnpm@10.0.1", "pnpm@11.0.0", "pnpm@11.28.9", "pnpm@12.0.0", "pnpm@12.18.0"} {
		if !PNPMHint(hint) || SupportsPNPM(hint) {
			t.Fatal(hint)
		}
	}
	for _, hint := range []string{"pnpm@lockfile-9", "pnpm@8.0.0", "pnpm@13.0.0", "pnpm@12.18.0-beta", "pnpm@12.18.0+build", "pnpm@11.28.9-beta", "pnpm@11.28.9+build", "pnpm@09.15.9", "pnpm@9.015.9", "pnpm@9.15.09", "pnpm@9.15.9-beta", "pnpm@10.34.9+sha512.foo", "pnpm@9.x", "pnpm@9.1.4294967296"} {
		if PNPMHint(hint) {
			t.Fatal(hint)
		}
	}
	if !SupportsPNPM(PNPMFormat9) {
		t.Fatal("format profile missing")
	}
}
