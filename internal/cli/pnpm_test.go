package cli

import "testing"

func TestPNPMScanArguments(t *testing.T) {
	for _, manager := range []string{"pnpm", "pnpm@lockfile-9"} {
		got, err := ParseArgs([]string{"scan", "--manager", manager, "owned-unused"})
		if err != nil || got.Scan.Manager != manager {
			t.Fatal(got, err)
		}
	}
	for _, manager := range []string{"pnpm@9.15.9", "pnpm@10.34.9", "pnpm@lockfile-8"} {
		if _, err := ParseArgs([]string{"scan", "--manager", manager, "owned-unused"}); err == nil {
			t.Fatal("producer is not format profile", manager)
		}
	}
}
