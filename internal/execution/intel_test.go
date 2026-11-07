package execution

import (
	"context"
	"os"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"strings"
	"testing"
	"time"
)

func TestIntelLaunchCannotInventAnInternalRole(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{saved[0], WorkerArgument}
	t.Setenv(launchRole, "invented")
	t.Setenv(launchNonce, strings.Repeat("0", 64))
	t.Setenv(launchHandle, "3")
	t.Setenv(launchData, "")
	if _, _, e := launchCapability("invented"); e == nil {
		t.Fatal("unknown private role accepted")
	}
}
func TestIntelObservationRejectsUnclosedClaimsCountsAndGaps(t *testing.T) {
	good := intelstore.Observation{Generation: strings.Repeat("a", 64), SourceAuthority: intelstore.SourceUnqualified, Check: intel.FreshnessUnknown, FullReconciliation: intel.FreshnessUnknown, Gaps: []intelstore.Gap{intelstore.GapSourceUnqualified, intelstore.GapCheckUnknown, intelstore.GapFullUnknown}}
	if e := validateIntelObservation(good); e != nil {
		t.Fatal(e)
	}
	bad := good
	bad.SourceAuthority = "marker-trusted"
	if validateIntelObservation(bad) == nil {
		t.Fatal("unknown source authority accepted")
	}
	bad = good
	bad.Records = 2_000_001
	if validateIntelObservation(bad) == nil {
		t.Fatal("count ceiling widened")
	}
	bad = good
	bad.Gaps = nil
	if validateIntelObservation(bad) == nil {
		t.Fatal("gaps silently suppressed")
	}
	bad = good
	bad.Check = intel.FreshnessCurrent
	if validateIntelObservation(bad) == nil {
		t.Fatal("unqualified source claimed freshness")
	}
}
func TestIntelResidentMonitorAdmitsOwnWindowWithoutWideningScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	sample := residentSample{ElapsedMS: 6 * 60 * 1000, Bytes: 1, Valid: true}
	legacy := newScanMonitor(cancel)
	if legacy.sample(sample) == nil {
		t.Fatal("legacy window widened")
	}
	prepared := newIntelMonitor(cancel)
	if e := prepared.sample(sample); e != nil {
		t.Fatal("15min role rejected its own elapsed window", e)
	}
}
func TestIntelPreparationDeadlineDoesNotWidenLegacyRoles(t *testing.T) {
	ctx := context.Background()
	legacy := newRunState(ctx)
	prepared := newIntelRunState(ctx)
	if time.Until(legacy.deadline) > 5*time.Minute || time.Until(prepared.deadline) < 14*time.Minute || time.Until(prepared.deadline) > 15*time.Minute {
		t.Fatal("fixed role deadline changed")
	}
	earlier, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second))
	defer cancel()
	limited := newIntelRunState(earlier)
	if time.Until(limited.deadline) > time.Second {
		t.Fatal("preparation renewed caller deadline")
	}
}
