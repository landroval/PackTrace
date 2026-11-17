package integrityscan

import (
	"context"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"sort"
)

// Used only after validated exact construction binds every block, including
// empty blocks. It does not establish source authority or category semantics.
func walkSelectedAdvisoryOriginals(ctx context.Context, snapshot *intelstore.Snapshot, selected map[string]bool, remaining uint64, emit func(uint64, intel.SnapshotOriginalEvidence) error) (uint64, error) {
	var groups [256][]string
	for name := range selected {
		bucket, err := intel.SnapshotNPMIdentityBlock(name)
		if err != nil {
			return 0, err
		}
		groups[bucket] = append(groups[bucket], name)
	}
	seen := map[uint64][32]byte{}
	var consumed uint64
	for _, names := range groups {
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		used, err := snapshot.WalkIdentities(ctx, names, remaining-consumed, func(name string, evidence intel.SnapshotNPMEvidence) error {
			if matchingIdentityScopeGap(evidence) != "" {
				return ErrAdvisory
			}
			for _, record := range evidence.Records {
				if len(record.Bindings) == 0 {
					return ErrAdvisory
				}
				for _, binding := range record.Bindings {
					if binding.State != intel.SnapshotBindingEligible {
						return ErrAdvisory
					}
					if digest, ok := seen[binding.SourceOrdinal]; ok {
						if digest != record.SHA256 {
							return ErrAdvisory
						}
						continue
					}
					// Retained selected ordinals still use the existing 1024 original cap.
					if len(seen) == 1024 {
						return ErrAdvisory
					}
					seen[binding.SourceOrdinal] = record.SHA256
					if err := emit(binding.SourceOrdinal, record); err != nil {
						return err
					}
				}
			}
			return nil
		})
		consumed += used
		if err != nil {
			return consumed, err
		}
	}
	return consumed, nil
}
