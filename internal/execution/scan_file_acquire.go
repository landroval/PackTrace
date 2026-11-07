package execution

import (
	"context"
	"errors"
	"path/filepath"

	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

// File output is admitted against the SAME roots that acquire the inputs. A
// separate metadata root opened only to pass a binding check would not suffice.
func acquireBoundFileScan(ctx context.Context, cfg scanConfig, owner *scanIntelligenceOwner, emit func(integrityscan.Record) error, emitInventory func(projectinventory.Result) error, emitEvidence integrityscan.PolicyEvidenceEmitter) (summary integrityscan.Summary, failure error) {
	if cfg.Plan == nil || cfg.FileOutput == nil {
		return summary, errOutput
	}
	var target *nativefs.Root
	if owner != nil {
		target = owner.target
	} else {
		var err error
		target, err = nativefs.OpenRoot(ctx, cfg.Target)
		if err != nil {
			return summary, err
		}
		defer func() { failure = errors.Join(failure, target.Close()) }()
	}
	prepared := ""
	if !cfg.Plan.Builtin {
		prepared = filepath.Dir(cfg.PolicyPath)
	}
	admit := func(reference *nativefs.Root) (func() error, error) {
		plan, err := bindScanFileAcquisition(ctx, target, owner, reference, cfg.FileOutput)
		if err != nil {
			return nil, err
		}
		return func() error { return errors.Join(plan.Check(), plan.Close()) }, nil
	}
	return integrityscan.AcquireFromRootWithPolicyEvidenceAdmission(ctx, target, prepared, cfg.PolicyHash, *cfg.Plan, emit, emitInventory, emitEvidence, admit)
}
