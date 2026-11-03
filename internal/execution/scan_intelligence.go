package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"packtrace/internal/integrityscan"
	"packtrace/internal/intel"
	"packtrace/internal/intelstore"
	"packtrace/internal/nativefs"
	"path/filepath"
	"time"
)

// Tokens are continuity checks between two independently admitted roots, never
// stand-alone authority. The controller retains its actual roots/lease to reap.
type scanIntelligenceConfig struct {
	Path          string `json:"path"`
	TrustedDigest string `json:"trustedDigest"`
	Generation    string `json:"generation"`
	Binding       string `json:"binding"`
	TargetBinding string `json:"targetBinding"`
	Selection     string `json:"selection"`
	NowUnixNS     int64  `json:"nowUnixNS"`
}
type scanIntelligenceClosure struct {
	States int `json:"states"`
}
type scanIntelligenceOwner struct {
	target   *nativefs.Root
	metadata *nativefs.MetadataLease
	store    *intelstore.Store
	pin      *intelstore.Pin
	cfg      scanIntelligenceConfig
	closed   bool
	closeErr error
}

func scanStateAbsent(ctx context.Context, target *nativefs.Root, path string) (absent bool, failure error) {
	parent, e := target.OpenExternalRoot(ctx, filepath.Dir(path))
	if e != nil {
		return false, intelstore.ErrBinding
	}
	defer func() { failure = errors.Join(failure, parent.Close()) }()
	cursor, e := parent.OpenDirectoryMetadata(ctx, ".")
	if e != nil {
		return false, e
	}
	defer func() { failure = errors.Join(failure, cursor.Close()) }()
	var count int
	for {
		batch, e := cursor.Next()
		if e != nil && e != io.EOF {
			return false, e
		}
		for _, entry := range batch {
			count++
			if count > 100_000 {
				return false, intelstore.ErrLimit
			}
			if entry.Name == filepath.Base(path) {
				return false, nil
			}
		}
		if e == io.EOF {
			return true, nil
		}
	}
}
func openScanIntelligence(ctx context.Context, targetPath, statePath, digest string, forced *intelstore.ID) (owner *scanIntelligenceOwner, failure error) {
	target, e := nativefs.OpenRoot(ctx, targetPath)
	if e != nil {
		return nil, e
	}
	owner = &scanIntelligenceOwner{target: target, cfg: scanIntelligenceConfig{Path: statePath, TrustedDigest: digest, Selection: "none", NowUnixNS: time.Now().UnixNano()}}
	fail := func(e error) (*scanIntelligenceOwner, error) { return owner, e }
	owner.metadata, e = target.OpenMetadata(ctx, ".")
	if e != nil {
		return fail(e)
	}
	token, e := owner.metadata.Fingerprint()
	if e != nil {
		return fail(e)
	}
	owner.cfg.TargetBinding = hex.EncodeToString(token[:])
	owner.store, e = intelstore.OpenExternal(ctx, target, statePath)
	if e != nil {
		if errors.Is(e, intelstore.ErrBinding) {
			absent, check := scanStateAbsent(ctx, target, statePath)
			if check != nil || !absent {
				return fail(intelstore.ErrBinding)
			}
		}
		return owner, nil
	}
	var selected *intelstore.ID
	if digest != "" {
		sum, e := intel.ParseSnapshotDigest(digest)
		if e != nil {
			return fail(e)
		}
		id := intelstore.ID(sum)
		selected = &id
	}
	if forced != nil {
		if selected != nil && *selected != *forced {
			return fail(intelstore.ErrBinding)
		}
		selected = forced
	}
	owner.pin, e = owner.store.Pin(ctx, selected)
	if e != nil {
		return owner, nil
	}
	id := owner.pin.ID()
	binding, e := owner.pin.PhysicalBinding(ctx)
	if e != nil {
		return fail(e)
	}
	owner.cfg.Generation = hex.EncodeToString(id[:])
	owner.cfg.Binding = hex.EncodeToString(binding[:])
	owner.cfg.Selection = "current"
	if owner.pin.Fallback() {
		owner.cfg.Selection = "previous-fallback"
	}
	if digest != "" {
		owner.cfg.Selection = "expected-digest"
	}
	return owner, nil
}
func (o *scanIntelligenceOwner) check(ctx context.Context) error {
	if o == nil || o.closed || o.metadata == nil {
		return intelstore.ErrBinding
	}
	target, e := o.metadata.Fingerprint()
	if e != nil || hex.EncodeToString(target[:]) != o.cfg.TargetBinding {
		return intelstore.ErrBinding
	}
	if o.pin != nil {
		binding, e := o.pin.PhysicalBinding(ctx)
		if e != nil || hex.EncodeToString(binding[:]) != o.cfg.Binding {
			return intelstore.ErrBinding
		}
	}
	return nil
}
func (o *scanIntelligenceOwner) close() error {
	if o == nil {
		return nil
	}
	if o.closed {
		return o.closeErr
	}
	o.closed = true
	var e error
	if o.pin != nil {
		e = errors.Join(e, o.pin.Close())
	}
	if o.store != nil {
		e = errors.Join(e, o.store.Close())
	}
	if o.metadata != nil {
		e = errors.Join(e, o.metadata.Close())
	}
	if o.target != nil {
		e = errors.Join(e, o.target.Close())
	}
	o.closeErr = e
	return e
}
func workerScanIntelligence(ctx context.Context, targetPath string, cfg scanIntelligenceConfig) (owner *scanIntelligenceOwner, info integrityscan.Intelligence, failure error) {
	info = integrityscan.UnavailableIntelligence()
	var forced *intelstore.ID
	if cfg.Generation != "" {
		if !intelResultID(cfg.Generation) {
			return nil, info, errScanProtocol
		}
		raw, _ := hex.DecodeString(cfg.Generation)
		var id intelstore.ID
		copy(id[:], raw)
		forced = &id
	}
	owner, e := openScanIntelligence(ctx, targetPath, cfg.Path, cfg.TrustedDigest, forced)
	if e != nil {
		return owner, info, e
	}
	if owner.cfg.TargetBinding != cfg.TargetBinding || owner.cfg.Generation != cfg.Generation || owner.cfg.Binding != cfg.Binding {
		return owner, info, intelstore.ErrBinding
	}
	if owner.pin == nil {
		return owner, info, nil
	}
	id := owner.pin.ID()
	snapshot, e := owner.store.ReadPinned(ctx, &id)
	if e != nil {
		return owner, info, nil
	}
	defer func() { failure = errors.Join(failure, snapshot.Close()) }()
	var expected *intelstore.ID
	if cfg.TrustedDigest != "" {
		expected = &id
	}
	observed, e := snapshot.Observe(ctx, time.Unix(0, cfg.NowUnixNS), expected)
	if e != nil {
		return owner, info, nil
	}
	if cfg.Selection == "previous-fallback" {
		observed.Fallback = true
		gaps := observed.Gaps
		at := 0
		for at < len(gaps) && gaps[at] != intelstore.GapIdentity && gaps[at] != intelstore.GapTemporal && gaps[at] != intelstore.GapDisposition {
			at++
		}
		observed.Gaps = append(append(append([]intelstore.Gap{}, gaps[:at]...), intelstore.GapFallback), gaps[at:]...)
	}
	if validateIntelObservation(observed) != nil {
		return owner, info, errScanProtocol
	}
	info = integrityscan.SnapshotIntelligence(observed, cfg.Selection)
	if integrityscan.ValidateIntelligence(info) != nil {
		return owner, integrityscan.UnavailableIntelligence(), errScanProtocol
	}
	return owner, info, nil
}
