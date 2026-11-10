package cli

import "testing"

func TestExpandedManagerArgumentsStayClosed(t *testing.T) {
	for _, manager := range []string{"npm@7.24.2", "npm@8.0.0", "npm@9.9.4", "npm@7-11", "npm@10-11", "npm@12.x", "bun@1.2.23", "bun@1.4.3", "bun@1.2.x", "bun@1.3.x", "bun@1.4.x", "bun@1.2-1.4"} {
		got, e := ParseArgs([]string{"scan", "--manager", manager, "owned"})
		if e != nil || got.Scan.Manager != manager {
			t.Fatal("supported manager rejected", manager, e)
		}
	}
	for _, manager := range []string{"npm@6.14.18", "npm@13.0.0", "npm@7-12", "npm@7.24.2-rc.1", "bun@1.1.39", "bun@1.5.0", "bun@1.2.23+hash"} {
		if _, e := ParseArgs([]string{"scan", "--manager", manager, "owned"}); e == nil {
			t.Fatal("unsupported manager accepted", manager)
		}
	}
}
