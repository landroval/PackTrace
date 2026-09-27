{
  "id": "f5d2ffe1",
  "title": "Increment 8: OSV temporal projection complete",
  "tags": [],
  "status": "closed",
  "created_at": "2026-09-27T15:06:11.342Z"
}

# Execution ledger — [increment 8 plan](../../docs/increments/08-osv-times-plan.md)

Task 1 complete. User selected temporal/withdrawal scope, approved explicit profile specification and plan, then explicitly authorized two new Go files, inline execution/review, offline tests/vet and scoped code/docs commits.

Spec 9c051cdb; approved plan/base b83e9992; code 3e517794; completion docs 8a8378cb.

RED: missing API/types compile failure, then definitions/zero-result stub produced 72 runtime test/subtest failures. Behavior implemented afterward.
GREEN: 72 new temporal + 348 previous tests/subtests = 420 total, root vet passes; full tests/vet rerun after inline review. Module list only packtrace. Offline GOTOOLCHAIN=local GOPROXY=off GOWORK=off CGO_ENABLED=0, existing go1.27.1-X:nodwarf5 linux/amd64. Review not independent.

ProjectOSVTimes preserves modified/published/withdrawn text, source digest and five field states. Approved grammar: uppercase T/Z, explicit Z/numeric timezone, max 9 fractional digits, offset <=23:59, valid calendar, UTC-normalized year0000–9999. time.ParseInLocation(...,time.UTC) avoids time.Parse's implicit Local lookup. No clock/chronology/freshness inference. Zero time validity determined by state. Withdrawn absent => NotDeclared, supported timestamp => Reported, null/type/uninterpretable => Unknown; no active/matchable assertion.

Tests cover all states/classifications, zero instant, future withdrawal, nanoseconds/trailing zeros, positive/negative/-00 offsets, leap/calendar/lexical failures, excess precision, year crossings/out-of-range UTC, independent fields, raw ownership and nil guard. All old Go source/test files byte-identical to plan base; readers/decoder/module/probes untouched. No network, new dependency, target access or native qualification.

Docs: 84 local Markdown links, 85 shipping parents retained, only two documentary parents checked. Nested temporal milestone does not close corrections, matching, freshness or advisory qualification. Further increments require fresh approvals.
