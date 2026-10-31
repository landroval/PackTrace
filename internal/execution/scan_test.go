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
func TestScanSourceReceiptRejectsNonDigest(t *testing.T) {
	if scanSourceHash("sha256-"+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == false {
		t.Fatal("strong source hash rejected")
	}
	if scanSourceHash("sha256-" + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!") {
		t.Fatal("invalid source hash admitted")
	}
}
