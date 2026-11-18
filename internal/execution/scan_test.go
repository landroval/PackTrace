package execution

import (
	"context"
	"testing"
	"time"
)

func TestScanImmediateSampleAccountsBothResidentProcesses(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor := newScanMonitor(cancel)
	if e := monitor.sample(residentSample{ElapsedMS: 0, Bytes: 1 << 20, Valid: true}); e != nil {
		t.Fatal(e)
	}
	got := monitor.result()
	if got.WorkerSamples != 1 || got.SupervisorSamples < 1 || got.SupervisorPeakBytes == 0 || got.PeakSampledSumBytes <= 1<<20 {
		t.Fatalf("short-lived child never paired with parent RSS: %+v", got)
	}
}
func TestScanResidentStopsOnPairedThresholdAndExposesMissingSamples(t *testing.T) {
	for _, mode := range []string{"paired-threshold", "query-failure", "stale"} {
		t.Run(mode, func(t *testing.T) {
			_, cancel := context.WithCancel(context.Background())
			defer cancel()
			monitor := newScanMonitor(cancel)
			sample := residentSample{ElapsedMS: 0, Bytes: 1 << 20, Valid: true}
			switch mode {
			case "paired-threshold":
				sample.Bytes = 1 << 30
			case "query-failure":
				sample.Valid = false
				sample.Bytes = 0
			case "stale":
				monitor.last = time.Now().Add(-time.Second)
			}
			if e := monitor.sample(sample); e == nil {
				t.Fatalf("resource gap/threshold accepted %s: %+v", mode, monitor.result())
			}
			got := monitor.result()
			if mode == "paired-threshold" && !got.Stopped || mode == "query-failure" && !got.QueryFailed || mode == "stale" && !got.Stale {
				t.Fatal("resource cause lost", mode, got)
			}
		})
	}
}
func TestScanFirstStaleDiagnosticDoesNotRelaxGuard(t *testing.T) {
	for _, stage := range []string{"protocol-own-gap", "protocol-sample-gap", "protocol-no-sample"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lifecycle := &scanLifecycle{ctx: ctx, caller: ctx, started: time.Now(), active: -1}
			monitor := newScanMonitor(cancel)
			monitor.noteStale = lifecycle.noteProtocolStale
			monitor.operation("npm-root-original")
			monitor.last = time.Now().Add(-time.Second)
			switch stage {
			case "protocol-own-gap":
				monitor.own()
			case "protocol-sample-gap":
				if monitor.sample(residentSample{Bytes: 1, Valid: true}) != errScanResource {
					t.Fatal("stale sample accepted")
				}
			case "protocol-no-sample":
				monitor.result()
			}
			first := lifecycle.snapshot().FirstFault
			monitor.operation("PRIVATE-child-controlled-label")
			monitor.result()
			got := lifecycle.snapshot().FirstFault
			if !monitor.result().Stale || got != first || got.Stage != stage || got.SampleGap < time.Second || got.Operation != "npm-root-original" || got.OperationElapsed <= 0 {
				t.Fatalf("first stale cause lost or guard relaxed: %+v", got)
			}
			if monitor.operationName != "other" {
				t.Fatal("unbounded diagnostic label")
			}
		})
	}
}

func TestScanSourceReceiptRejectsNonDigest(t *testing.T) {
	if scanSourceHash("sha256-"+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == false {
		t.Fatal("strong source hash rejected")
	}
	if scanSourceHash("sha256-" + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") {
		t.Fatal("invalid source hash admitted")
	}
}
