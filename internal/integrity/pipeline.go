package integrity

import (
	"context"
	"errors"
)

// AssessIntegrity processes inert caller evidence; it does not inspect a native target.
// Read budgets are debited from actual archive counters even when inspection fails.
func AssessIntegrity(ctx context.Context, requests []AssessmentRequest, l Limits) (Assessment, error) {
	if ctx == nil {
		return Assessment{}, errors.New("nil integrity context")
	}
	var e error
	l, e = normalizedLimits(l)
	if e != nil {
		return Assessment{}, e
	}
	a := Assessment{NativeQualification: "not-run", SuppliedComparisonComplete: len(requests) > 0, Instances: make([]InstanceAssessment, 0, len(requests))}
	readBudget, expandedBudget := l.ReferenceReadBytes, l.AggregateExpandedBytes
	seen := make(map[string]bool, len(requests))
	for _, request := range requests {
		id := request.Binding.InstanceID
		instance := InstanceAssessment{InstanceID: id}
		binding, gaps := ResolveReferenceBinding(request.Binding)
		if len(gaps) > 0 {
			instance.Gaps = appendGap(instance.Gaps, gaps[0])
			a.Instances = append(a.Instances, instance)
			a.SuppliedComparisonComplete = false
			continue
		}
		if seen[id] {
			instance.Gaps = appendGap(instance.Gaps, Gap{Code: GapBinding, InstanceID: id})
			a.Instances = append(a.Instances, instance)
			a.SuppliedComparisonComplete = false
			continue
		}
		seen[id] = true
		if request.Archive == nil || readBudget <= 0 || expandedBudget <= 0 || ctx.Err() != nil {
			instance.Gaps = appendGap(instance.Gaps, Gap{Code: GapReference, InstanceID: id})
			a.Instances = append(a.Instances, instance)
			a.SuppliedComparisonComplete = false
			continue
		}
		limits := l
		limits.ReferenceReadBytes = min(limits.ReferenceReadBytes, readBudget)
		limits.AggregateExpandedBytes = min(limits.AggregateExpandedBytes, expandedBudget)
		catalog, archiveErr := InspectReferenceArchive(ctx, binding, request.Archive, limits)
		readBudget -= catalog.CompressedRead
		expandedBudget -= catalog.ExpandedRead
		if archiveErr != nil || !catalog.verified || readBudget < 0 || expandedBudget < 0 {
			instance.Gaps = appendGap(instance.Gaps, Gap{Code: GapReference, InstanceID: id})
			a.Instances = append(a.Instances, instance)
			a.SuppliedComparisonComplete = false
			continue
		}
		instance, e = CompareReferenceCatalog(binding, catalog, request.Installed)
		if e != nil {
			instance = InstanceAssessment{InstanceID: id, Gaps: []Gap{{Code: GapReference, InstanceID: id}}}
		}
		if !instance.SuppliedComparisonComplete {
			a.SuppliedComparisonComplete = false
		}
		a.Instances = append(a.Instances, instance)
	}
	return a, nil
}
