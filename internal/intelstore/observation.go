package intelstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"packtrace/internal/intel"
	"time"
)

type SourceAuthority string

const (
	SourceUnqualified SourceAuthority = "unqualified"
	SourceLocal       SourceAuthority = "local-acquisition"
	SourceDesignated  SourceAuthority = "operator-designated"
)

type Gap string

const (
	GapSourceUnqualified Gap = "source-unqualified"
	GapCheckUnknown      Gap = "source-check-unknown"
	GapCheckExpired      Gap = "source-check-expired"
	GapFullUnknown       Gap = "full-reconciliation-unknown"
	GapFullExpired       Gap = "full-reconciliation-expired"
	GapFallback          Gap = "previous-generation-fallback"
	GapIdentity          Gap = "identity-unqualified"
	GapTemporal          Gap = "advisory-time-unqualified"
	GapDisposition       Gap = "known-id-unresolved"
)

type Observation struct {
	Generation                                                        string               `json:"generation"`
	SourceAuthority                                                   SourceAuthority      `json:"sourceAuthority"`
	Check                                                             intel.FreshnessState `json:"check"`
	FullReconciliation                                                intel.FreshnessState `json:"fullReconciliation"`
	Records, Memberships, IdentityGaps, TemporalGaps, DispositionGaps uint64
	Fallback                                                          bool  `json:"fallback"`
	Gaps                                                              []Gap `json:"gaps"`
}

func licenseProfile(receipt sourceReceipt, prep preparationRecord) bool {
	if receipt.Source != "osv-npm" || receipt.PublisherAuthentication != "not-established" || prep.UnknownPublisherRecords != 0 || prep.GitHubRecords > prep.Records || prep.OpenSSFRecords > prep.Records || prep.GitHubRecords+prep.OpenSSFRecords != prep.Records || len(receipt.Attributions) > 2 {
		return false
	}
	github, openssf := false, false
	for _, a := range receipt.Attributions {
		switch a.License {
		case "CC-BY-4.0":
			if github || a.Publisher != "GitHub Advisory Database" || a.Text.SHA256 != sha256.Sum256(githubLicense) || a.Text.Bytes != uint64(len(githubLicense)) {
				return false
			}
			github = true
		case "Apache-2.0":
			if openssf || a.Publisher != "OpenSSF Malicious Packages contributors" || a.Text.SHA256 != sha256.Sum256(openssfLicense) || a.Text.Bytes != uint64(len(openssfLicense)) {
				return false
			}
			openssf = true
		default:
			return false
		}
	}
	return github == (prep.GitHubRecords > 0) && openssf == (prep.OpenSSFRecords > 0)
}

// Observe is readonly and uses an already retained generation. An expected ID
// is authority supplied by this invocation, never a field decoded from storage.
func (s *Store) Observe(ctx context.Context, pin *Pin, now time.Time, expected *ID) (Observation, error) {
	var result Observation
	if s == nil || pin == nil || ctx == nil {
		return result, ErrUnavailable
	}
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.closed || pin.store != s || pin.lease == nil {
		return result, ErrBinding
	}
	id := pin.id
	key := hex.EncodeToString(id[:])
	if pin.lease.Matches(ctx, s.root, "generations/"+key+"/read.lock", false) != nil {
		return result, ErrBinding
	}
	if expected != nil && *expected != id {
		return result, ErrUntrusted
	}
	header, e := s.explicitHeader(ctx, id)
	if e != nil {
		return result, e
	}
	raw, e := s.readRef(ctx, header.Descriptor, 4096)
	if e != nil {
		return result, e
	}
	descriptor, e := parseGenerationDescriptor(raw)
	if e != nil {
		return result, e
	}
	raw, e = s.readRef(ctx, descriptor.Manifest, 1<<20)
	if e != nil {
		return result, e
	}
	manifest, e := intel.ParseSnapshotManifestV11(raw)
	if e != nil {
		return result, ErrCorrupt
	}
	result.Generation = key
	result.SourceAuthority = SourceUnqualified
	result.Records = manifest.Originals.Records
	result.Fallback = pin.fallback
	for _, b := range manifest.Blocks {
		if b.Reference.Records > 2_000_000-result.Memberships {
			return Observation{}, ErrCorrupt
		}
		result.Memberships += b.Reference.Records
	}
	var prep preparationRecord
	var receipt sourceReceipt
	sourceProfile := false
	if !zeroRef(descriptor.Provenance) {
		raw, e = s.readRef(ctx, descriptor.Provenance, 32<<10)
		if e != nil {
			return Observation{}, e
		}
		if json.Unmarshal(raw, &receipt) == nil && receipt.Version == 1 && receipt.Source == "osv-npm" {
			sourceProfile = true
			raw, e = s.readRef(ctx, receipt.Preparation, 512<<10)
			if e != nil {
				return Observation{}, e
			}
		}
		if json.Unmarshal(raw, &prep) != nil || prep.Version != 1 || prep.Records != result.Records || prep.Memberships != result.Memberships || prep.IdentityGaps > 2_000_000*64 || prep.TemporalGaps > prep.Records || prep.DispositionGaps > prep.Records {
			return Observation{}, ErrCorrupt
		}
		result.IdentityGaps, result.TemporalGaps, result.DispositionGaps = prep.IdentityGaps, prep.TemporalGaps, prep.DispositionGaps
	}
	sourceProfile = sourceProfile && licenseProfile(receipt, prep) && manifest.Source.ID == "osv-npm" && manifest.Source.LastSuccessfulCheck.State == intel.TimestampValue && manifest.Source.LastSuccessfulCheck.Value.Equal(receipt.CheckedAt)
	if receipt.FullReconciliationEstablished {
		sourceProfile = sourceProfile && manifest.Source.LastFullReconciliation.State == intel.TimestampValue && manifest.Source.LastFullReconciliation.Value.Equal(receipt.ReconciledAt)
	} else {
		sourceProfile = sourceProfile && manifest.Source.LastFullReconciliation.State == intel.TimestampAbsent
	}
	if sourceProfile {
		if s.verifyLocal(ctx, id) == nil {
			result.SourceAuthority = SourceLocal
		} else if expected != nil {
			result.SourceAuthority = SourceDesignated
		}
	}
	ages := intel.EvaluateSnapshotFreshness(manifest.Source, now, result.SourceAuthority != SourceUnqualified)
	result.Check, result.FullReconciliation = ages.Check, ages.FullReconciliation
	if result.SourceAuthority == SourceUnqualified {
		result.Gaps = append(result.Gaps, GapSourceUnqualified)
	}
	if result.Check == intel.FreshnessUnknown {
		result.Gaps = append(result.Gaps, GapCheckUnknown)
	} else if result.Check == intel.FreshnessExpired {
		result.Gaps = append(result.Gaps, GapCheckExpired)
	}
	if result.FullReconciliation == intel.FreshnessUnknown {
		result.Gaps = append(result.Gaps, GapFullUnknown)
	} else if result.FullReconciliation == intel.FreshnessExpired {
		result.Gaps = append(result.Gaps, GapFullExpired)
	}
	if result.Fallback {
		result.Gaps = append(result.Gaps, GapFallback)
	}
	if result.IdentityGaps > 0 {
		result.Gaps = append(result.Gaps, GapIdentity)
	}
	if result.TemporalGaps > 0 {
		result.Gaps = append(result.Gaps, GapTemporal)
	}
	if result.DispositionGaps > 0 {
		result.Gaps = append(result.Gaps, GapDisposition)
	}
	return result, nil
}
