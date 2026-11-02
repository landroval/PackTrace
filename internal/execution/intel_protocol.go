package execution

import (
	"encoding/hex"
	"errors"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"strings"
)

const IntelWorkerArgument = "--internal-intel-worker-v1"

var errIntelProtocol = errors.New("intel: worker-protocol")

func intelResultID(v string) bool {
	raw, e := hex.DecodeString(v)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == v && v != strings.Repeat("0", 64)
}
func validateIntelObservation(v intelstore.Observation) error {
	if !intelResultID(v.Generation) || v.Records > 2_000_000 || v.Memberships > 2_000_000 || v.Records == 0 && v.Memberships != 0 || v.IdentityGaps > 2_000_000*64 || v.TemporalGaps > v.Records || v.DispositionGaps > v.Records {
		return errIntelProtocol
	}
	switch v.SourceAuthority {
	case intelstore.SourceUnqualified, intelstore.SourceLocal, intelstore.SourceDesignated:
	default:
		return errIntelProtocol
	}
	for _, state := range []intel.FreshnessState{v.Check, v.FullReconciliation} {
		if state != intel.FreshnessUnknown && state != intel.FreshnessCurrent && state != intel.FreshnessExpired {
			return errIntelProtocol
		}
	}
	if v.SourceAuthority == intelstore.SourceUnqualified && (v.Check != intel.FreshnessUnknown || v.FullReconciliation != intel.FreshnessUnknown) {
		return errIntelProtocol
	}
	var gaps []intelstore.Gap
	if v.SourceAuthority == intelstore.SourceUnqualified {
		gaps = append(gaps, intelstore.GapSourceUnqualified)
	}
	if v.Check == intel.FreshnessUnknown {
		gaps = append(gaps, intelstore.GapCheckUnknown)
	} else if v.Check == intel.FreshnessExpired {
		gaps = append(gaps, intelstore.GapCheckExpired)
	}
	if v.FullReconciliation == intel.FreshnessUnknown {
		gaps = append(gaps, intelstore.GapFullUnknown)
	} else if v.FullReconciliation == intel.FreshnessExpired {
		gaps = append(gaps, intelstore.GapFullExpired)
	}
	if v.Fallback {
		gaps = append(gaps, intelstore.GapFallback)
	}
	if v.IdentityGaps != 0 {
		gaps = append(gaps, intelstore.GapIdentity)
	}
	if v.TemporalGaps != 0 {
		gaps = append(gaps, intelstore.GapTemporal)
	}
	if v.DispositionGaps != 0 {
		gaps = append(gaps, intelstore.GapDisposition)
	}
	if len(gaps) != len(v.Gaps) {
		return errIntelProtocol
	}
	for i, gap := range gaps {
		if v.Gaps[i] != gap {
			return errIntelProtocol
		}
	}
	return nil
}
