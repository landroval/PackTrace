package intelstore

import (
	"errors"
	"testing"
)

func TestReservationIncludesRetainedStagingAndOverflow(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		used, held, add, limit uint64
		want                   bool
	}{
		{"retained-plus-staging", 7, 2, 2, 10, false},
		{"exact-capacity", 7, 2, 1, 10, true},
		{"full-zero-reservation", 10, 0, 0, 10, true},
		{"overflow-used", ^uint64(0), 1, 1, 10, false},
		{"overflow-held", 0, ^uint64(0), 1, 10, false},
		{"max-exact", ^uint64(0) - 1, 0, 1, ^uint64(0), true},
		{"max-overflow", ^uint64(0), 1, 0, ^uint64(0), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := canReserve(tt.used, tt.held, tt.add, tt.limit); got != tt.want {
				t.Fatal("quota reservation decision", got, tt.want)
			}
		})
	}
}

func TestQuotaUnknownIsNotSuccessfulZero(t *testing.T) {
	unknown := quotaObservation{}
	if _, err := unknown.reserve(1, 32<<30); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown accounting admitted write", err)
	}
	known := quotaObservation{used: 7, held: 2, complete: true}
	next, err := known.reserve(1, 10)
	if err != nil || next.used != 7 || next.held != 3 || !next.complete {
		t.Fatal("exact reservation accounting", err)
	}
	if known.held != 2 {
		t.Fatal("reservation mutated prior evidence")
	}
	if _, err := next.reserve(1, 10); !errors.Is(err, ErrLimit) {
		t.Fatal("quota exceeded", err)
	}
}
