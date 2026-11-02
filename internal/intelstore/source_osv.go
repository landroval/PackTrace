package intelstore

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"packtrace/internal/intel"
	"packtrace/internal/jsoninput"
	"packtrace/internal/nativefs"
	"strconv"
	"time"
)

//go:embed licenses/CC-BY-4.0-GitHub.txt
var githubLicense []byte

//go:embed licenses/Apache-2.0-OpenSSF.txt
var openssfLicense []byte

//go:embed licenses/CC0-1.0-GSD.txt
var gsdLicense []byte

type OperationResult struct {
	Generation           ID
	Records, Memberships uint64
	point                cursorPoint
}
type sourceFetch func(context.Context, *Budget, requestSpec, io.Writer) (responseEvidence, error)
type exportMetadata struct {
	Generation string
	Size       uint64
	MD5        [16]byte
	Updated    time.Time
}
type sourceAttribution struct {
	Publisher, License, OriginURL, LicenseURL, Changes string
	Text                                               ObjectRef
}
type sourceReceipt struct {
	Version                                      int
	Source, Acquisition, PublisherAuthentication string
	AcquiredAt, CheckedAt, ReconciledAt          time.Time
	FullReconciliationEstablished                bool
	ArchiveSHA256                                [32]byte
	ArchiveBytes                                 uint64
	Generation                                   string
	Metadata, Preparation                        ObjectRef
	Attributions                                 []sourceAttribution
}

func successfulCheckTime(old, now time.Time, verified bool) time.Time {
	if !verified || now.Before(old) {
		return old
	}
	return now
}
func parseExportMetadata(data []byte) (exportMetadata, error) {
	return parseSourceMetadata(data, requestArchive)
}
func parseSourceMetadata(data []byte, kind requestKind) (exportMetadata, error) {
	name, contentType, limit := "npm/all.zip", "application/zip", uint64(1<<30)
	if kind == requestChanges {
		name, contentType, limit = "modified_id.csv", "text/csv", 256<<20
	} else if kind != requestArchive {
		return exportMetadata{}, ErrUntrusted
	}
	fields, code := jsoninput.Object(data, 512<<10)
	if code != "" {
		return exportMetadata{}, ErrCorrupt
	}
	var wire struct{ Kind, Bucket, Name, Generation, Size, MD5Hash, Updated, ContentType string }
	for _, field := range []struct {
		key   string
		value *string
	}{{"kind", &wire.Kind}, {"bucket", &wire.Bucket}, {"name", &wire.Name}, {"generation", &wire.Generation}, {"size", &wire.Size}, {"md5Hash", &wire.MD5Hash}, {"updated", &wire.Updated}, {"contentType", &wire.ContentType}} {
		raw, ok := fields[field.key]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, field.value) != nil {
			return exportMetadata{}, ErrCorrupt
		}
	}
	if wire.Kind != "storage#object" || wire.Bucket != "osv-vulnerabilities" || wire.Name != name || wire.ContentType != contentType {
		return exportMetadata{}, ErrUntrusted
	}
	generation, e := strconv.ParseUint(wire.Generation, 10, 64)
	if e != nil || generation == 0 || strconv.FormatUint(generation, 10) != wire.Generation {
		return exportMetadata{}, ErrCorrupt
	}
	size, e := strconv.ParseUint(wire.Size, 10, 64)
	if e != nil || size == 0 || size > limit || strconv.FormatUint(size, 10) != wire.Size {
		return exportMetadata{}, ErrLimit
	}
	digest, e := base64.StdEncoding.DecodeString(wire.MD5Hash)
	if e != nil || len(digest) != 16 || base64.StdEncoding.EncodeToString(digest) != wire.MD5Hash {
		return exportMetadata{}, ErrCorrupt
	}
	updated := intel.ProjectOSVTimestampText(wire.Updated)
	if updated.State != intel.TimestampValue {
		return exportMetadata{}, ErrCorrupt
	}
	result := exportMetadata{Generation: wire.Generation, Size: size, Updated: updated.Value}
	copy(result.MD5[:], digest)
	return result, nil
}
func (t *Transaction) stageSourceObject(input io.Reader, max uint64, kind requestKind) (*nativefs.OwnedFile, [32]byte, [16]byte, error) {
	name, limit := "source-archive", uint64(1<<30)
	if kind == requestChanges {
		name, limit = "source-changes", 256<<20
	} else if kind != requestArchive {
		return nil, [32]byte{}, [16]byte{}, ErrUntrusted
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var sha [32]byte
	var md [16]byte
	if t.closed || t.failed != nil || max > limit || t.held < 4096 || max > t.held-4096 || t.writer.Matches(t.work, t.store.root, "writer.lock", true) != nil {
		return nil, sha, md, ErrLimit
	}
	if e := t.fence(t.work); e != nil {
		return nil, sha, md, e
	}
	h, m := sha256.New(), md5.New() // MD5 is only the selected GCS transport checksum.
	f, e := t.store.owner.CopyExclusive(t.work, t.path+"/"+name, io.TeeReader(input, io.MultiWriter(h, m)), max)
	if f != nil {
		n := uint64(f.Size())
		t.written += n
		if n > t.held {
			f.Close()
			t.failed = ErrLimit
			return nil, sha, md, ErrLimit
		}
		t.held -= n
	}
	if e == nil {
		e = f.Stable()
	}
	if e != nil {
		if f != nil {
			e = errors.Join(e, f.Close())
		}
		t.failed = ErrUnavailable
		return nil, sha, md, ErrUnavailable
	}
	copy(sha[:], h.Sum(nil))
	copy(md[:], m.Sum(nil))
	return f, sha, md, nil
}

type SyncOptions struct{ FullReconciliation bool }

func (s *Store) Sync(ctx context.Context, options SyncOptions) (OperationResult, error) {
	if options.FullReconciliation {
		return s.syncFull(ctx, &Budget{}, fetchPublic)
	}
	return s.sync(ctx, &Budget{}, fetchPublic)
}
func (s *Store) syncFull(ctx context.Context, b *Budget, fetch sourceFetch) (result OperationResult, failure error) {
	if fetch == nil {
		return result, ErrUnavailable
	}
	var previous *sourceState
	if pin, pinErr := s.Pin(ctx, nil); pinErr == nil {
		defer func() { failure = errors.Join(failure, pin.Close()) }()
		state, stateErr := s.loadSourceState(ctx, pin.ID())
		if stateErr == nil {
			previous = &state
		} else if s.verifyLocal(ctx, pin.ID()) == nil {
			return result, stateErr
		}
	} else if ctx != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	tx, e := s.begin(ctx, operationSync, b)
	if e != nil {
		return result, e
	}
	defer func() {
		if failure != nil {
			tx.mu.Lock()
			tx.failed = failure
			tx.mu.Unlock()
		}
		failure = errors.Join(failure, tx.Close())
	}()
	if previous != nil {
		selection, _, e := s.readSelection(tx.work)
		if e != nil || selection.Current != fmt.Sprintf("%x", previous.id) {
			return result, ErrBusy
		}
	}
	readMetadata := func() (exportMetadata, []byte, error) { return readSourceMetadata(tx.work, tx, requestArchive, fetch) }
	meta, metadataBytes, e := readMetadata()
	if e != nil {
		return result, e
	}
	original, archiveHash, e := captureSourceBody(tx.work, tx, requestArchive, meta, fetch)
	if e != nil {
		return result, e
	}
	defer func() { failure = errors.Join(failure, original.Close()) }()
	if previous != nil && previous.receipt.Generation == meta.Generation && (previous.receipt.ArchiveSHA256 != archiveHash || previous.receipt.ArchiveBytes != meta.Size) {
		return result, ErrUntrusted
	}
	draft, e := prepareArchive(tx.work, tx, original, original.Size())
	if e != nil {
		return result, e
	}
	// A whole candidate remains unusable when a required publisher/license is
	// unknown; never drop those records to make the known subset look complete.
	p := tx.prep.record
	if !knownPublisherCounts(p) {
		return result, ErrUntrusted
	}
	after, _, e := readMetadata()
	if e != nil || after != meta {
		return result, ErrUntrusted
	}
	if e := original.Stable(); e != nil {
		return result, ErrCorrupt
	}
	metadataRef, e := tx.put(tx.work, bytes.NewReader(metadataBytes), uint64(len(metadataBytes)))
	if e != nil {
		return result, e
	}
	receipt := sourceReceipt{Version: 1, Source: "osv-npm", Acquisition: "https-generation-bound", PublisherAuthentication: "not-established", ArchiveSHA256: archiveHash, ArchiveBytes: meta.Size, Generation: meta.Generation, Metadata: metadataRef, Preparation: draft.Provenance}
	draft, _, e = prepareListing(tx.work, tx, draft, p, meta.Updated, meta.Generation, nil, fetch)
	if e != nil {
		return result, e
	}
	if previous != nil {
		draft, e = reconcileKnown(tx.work, tx, draft, tx.prep.record, *previous, fetch)
		if e != nil {
			return result, e
		}
		receipt.CheckedAt = previous.receipt.CheckedAt
		receipt.ReconciledAt = previous.receipt.ReconciledAt
		receipt.FullReconciliationEstablished = previous.receipt.FullReconciliationEstablished
	}
	return publishSourceDraft(tx.work, tx, draft, receipt, meta.Updated, tx.prep.record.DispositionGaps == 0)
}
func publishSourceDraft(ctx context.Context, tx *Transaction, draft generationDraft, receipt sourceReceipt, exportedAt time.Time, full bool) (result OperationResult, failure error) {
	p := tx.prep.record
	if !knownPublisherCounts(p) {
		return result, ErrUntrusted
	}
	receipt.Preparation = draft.Provenance
	receipt.Attributions = nil
	for _, item := range publisherLicenses(p) {
		if item.count == 0 {
			continue
		}
		sum := sha256.Sum256(item.text)
		if hex.EncodeToString(sum[:]) != item.hash {
			return result, ErrUntrusted
		}
		ref, e := tx.put(tx.work, bytes.NewReader(item.text), uint64(len(item.text)))
		if e != nil {
			return result, e
		}
		draft.Objects = append(draft.Objects, ref)
		receipt.Attributions = append(receipt.Attributions, sourceAttribution{item.publisher, item.license, item.origin, item.licenseURL, sourceChanges, ref})
	}
	now := time.Now().UTC()
	receipt.AcquiredAt = now
	receipt.CheckedAt = successfulCheckTime(receipt.CheckedAt, now, true)
	if full {
		receipt.ReconciledAt = successfulCheckTime(receipt.ReconciledAt, now, true)
		receipt.FullReconciliationEstablished = true
	}
	// Only this private verified acquisition controller sets source dates; data
	// imported later still needs its independent invocation pin or local seal.
	raw, e := tx.store.readRef(tx.work, draft.Manifest, 1<<20)
	if e != nil {
		return result, e
	}
	var manifest map[string]any
	if json.Unmarshal(raw, &manifest) != nil {
		return result, ErrCorrupt
	}
	sourceFields := map[string]any{"id": "osv-npm", "acquisitionMethod": receipt.Acquisition, "acquiredAt": now.Format(time.RFC3339Nano), "exportedAt": exportedAt.UTC().Format(time.RFC3339Nano), "lastSuccessfulCheck": receipt.CheckedAt.Format(time.RFC3339Nano)}
	if receipt.FullReconciliationEstablished {
		sourceFields["lastFullReconciliation"] = receipt.ReconciledAt.Format(time.RFC3339Nano)
	}
	manifest["source"] = sourceFields
	manifestBytes, e := json.Marshal(manifest)
	if e != nil {
		return result, ErrCorrupt
	}
	manifestRef, e := tx.put(tx.work, bytes.NewReader(manifestBytes), uint64(len(manifestBytes)))
	if e != nil {
		return result, e
	}
	receiptBytes, e := json.Marshal(receipt)
	if e != nil {
		return result, ErrCorrupt
	}
	receiptRef, e := tx.put(tx.work, bytes.NewReader(receiptBytes), uint64(len(receiptBytes)))
	if e != nil {
		return result, e
	}
	draft.Objects = append(draft.Objects, receipt.Metadata, manifestRef, receiptRef)
	seen := make(map[[32]byte]uint64)
	objects := draft.Objects[:0]
	for _, ref := range draft.Objects {
		if old, ok := seen[ref.SHA256]; ok {
			if old != ref.Bytes {
				return result, ErrCorrupt
			}
			continue
		}
		seen[ref.SHA256] = ref.Bytes
		objects = append(objects, ref)
	}
	draft.Objects = objects
	draft.Manifest, draft.Provenance = manifestRef, receiptRef
	id, e := tx.seal(tx.work, draft)
	if e != nil {
		return result, e
	}
	if e := tx.attestLocal(tx.work, id); e != nil {
		return result, e
	}
	if e := tx.activate(tx.work, id); e != nil {
		return result, e
	}
	return OperationResult{Generation: id, Records: p.Records, Memberships: p.Memberships}, nil
}
