package cli

import (
	"fmt"
	"testing"
)

func TestSelectScanExit(t *testing.T) {
	for _, tc := range []struct {
		mask uint8
		want int
	}{
		{0b0000, 0}, {0b0001, 1}, {0b0010, 3}, {0b0011, 3},
		{0b0100, 2}, {0b0101, 2}, {0b0110, 2}, {0b0111, 2},
		{0b1000, 130}, {0b1001, 130}, {0b1010, 130}, {0b1011, 130},
		{0b1100, 130}, {0b1101, 130}, {0b1110, 130}, {0b1111, 130},
	} {
		t.Run(fmt.Sprintf("%04b", tc.mask), func(t *testing.T) {
			// I=bit3, E=bit2, C=bit1, F=bit0; expected codes are contract literals.
			conditions := ScanExitConditions{
				Interrupted:                tc.mask&8 != 0,
				ReportPreventingError:      tc.mask&4 != 0,
				RequiredCoverageIncomplete: tc.mask&2 != 0,
				EnforcedUnacceptedFindings: tc.mask&1 != 0,
			}
			if got := SelectScanExit(conditions); got != tc.want {
				t.Fatalf("conditions=%+v: want %d, got %d", conditions, tc.want, got)
			}
		})
	}
}
