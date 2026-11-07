package execution

import (
	"fmt"
	"packtrace/internal/cli"
	"packtrace/internal/intelstore"
)

// Only portable closed facts cross this boundary, never paths, URLs, raw
// records, license text or a child-selected public exit decision.
type IntelResult struct {
	Action       cli.ArgumentAction      `json:"action"`
	Outcome      string                  `json:"outcome"`
	Generation   string                  `json:"generation,omitempty"`
	Observation  *intelstore.Observation `json:"observation,omitempty"`
	Preview      *intelstore.Preview     `json:"preview,omitempty"`
	Prune        *intelstore.PruneResult `json:"prune,omitempty"`
	WrittenBytes uint64                  `json:"writtenBytes,omitempty"`
}

func validateIntelResult(v IntelResult, request cli.IntelArgumentRequest) error {
	switch request.Action {
	case cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelExport, cli.ArgumentActionIntelStatus, cli.ArgumentActionIntelPin, cli.ArgumentActionIntelUnpin, cli.ArgumentActionCachePrune:
	default:
		return errIntelProtocol
	}
	if v.Outcome == "complete" {
		switch request.Action {
		case cli.ArgumentActionIntelSync, cli.ArgumentActionIntelImport, cli.ArgumentActionIntelStatus:
			if v.Observation == nil || v.Generation == "" {
				return errIntelProtocol
			}
		case cli.ArgumentActionIntelExport:
			if v.Observation == nil || v.Generation == "" || v.WrittenBytes == 0 {
				return errIntelProtocol
			}
		case cli.ArgumentActionIntelPin, cli.ArgumentActionIntelUnpin:
			if !intelResultID(v.Generation) || v.Generation != request.Generation {
				return errIntelProtocol
			}
		case cli.ArgumentActionCachePrune:
			if request.ApplyPreview == "" && v.Preview == nil || request.ApplyPreview != "" && v.Prune == nil {
				return errIntelProtocol
			}
		}
	}
	if v.Action != request.Action || !one(v.Outcome, "complete", "unavailable", "busy", "limit", "corrupt", "untrusted", "interrupted") {
		return errIntelProtocol
	}
	if v.Generation != "" && !intelResultID(v.Generation) {
		return errIntelProtocol
	}
	if v.Observation != nil {
		if validateIntelObservation(*v.Observation) != nil || v.Generation != "" && v.Generation != v.Observation.Generation {
			return errIntelProtocol
		}
	}
	if v.WrittenBytes > 16<<30 || v.WrittenBytes != 0 && v.Action != cli.ArgumentActionIntelExport {
		return errIntelProtocol
	}
	if p := v.Preview; p != nil {
		if v.Action != cli.ArgumentActionCachePrune || request.ApplyPreview != "" || p.Token == (intelstore.ID{}) || p.Generations > 128 || p.Candidates > 100_000 || p.Generations > p.Candidates || p.Bytes > 32<<30 || p.QuarantinedBytes > 32<<30 || p.ReproducibilityRisk != (p.Generations > 0) {
			return errIntelProtocol
		}
	}
	if p := v.Prune; p != nil {
		if v.Action != cli.ArgumentActionCachePrune || request.ApplyPreview == "" || fmt.Sprintf("%x", p.Token) != request.ApplyPreview || p.Generations > 128 || p.RemovedFiles > p.QuarantinedFiles || p.QuarantinedFiles > 100_000 || p.RemovedBytes > 32<<30 || v.Outcome == "complete" && p.Partial {
			return errIntelProtocol
		}
	}
	if v.Action != cli.ArgumentActionCachePrune && (v.Prune != nil || v.Preview != nil) {
		return errIntelProtocol
	}
	if v.Prune != nil && v.Preview != nil {
		return errIntelProtocol
	}
	return nil
}
