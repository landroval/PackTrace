package intelstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"packtrace/internal/nativefs"
	"time"
)

func readSourceMetadata(ctx context.Context, t *Transaction, kind requestKind, fetch sourceFetch) (exportMetadata, []byte, error) {
	metadataKind := requestArchiveMeta
	if kind == requestChanges {
		metadataKind = requestChangesMeta
	} else if kind != requestArchive {
		return exportMetadata{}, nil, ErrUntrusted
	}
	var data bytes.Buffer
	ev, e := fetch(ctx, &t.budget, requestSpec{kind: metadataKind}, &data)
	if e != nil || ev.status != 200 || ev.bytes != uint64(data.Len()) {
		return exportMetadata{}, nil, ErrUnavailable
	}
	meta, e := parseSourceMetadata(data.Bytes(), kind)
	if e != nil {
		return meta, nil, e
	}
	if meta.Updated.After(time.Now()) {
		return meta, nil, ErrUntrusted
	}
	return meta, data.Bytes(), nil
}
func captureSourceBody(ctx context.Context, t *Transaction, kind requestKind, meta exportMetadata, fetch sourceFetch) (*nativefs.OwnedFile, [32]byte, error) {
	if kind != requestArchive && kind != requestChanges {
		return nil, [32]byte{}, ErrUntrusted
	}
	t.mu.Lock()
	available := !t.closed && t.failed == nil && t.held >= 4096 && meta.Size <= t.held-4096
	t.mu.Unlock()
	if !available {
		return nil, [32]byte{}, ErrLimit
	}
	reader, writer := io.Pipe()
	type outcome struct {
		evidence responseEvidence
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		ev, e := fetch(ctx, &t.budget, requestSpec{kind: kind, generation: meta.Generation}, writer)
		closeErr := writer.CloseWithError(e)
		done <- outcome{ev, errors.Join(e, closeErr)}
	}()
	original, sum, digest, copyErr := t.stageSourceObject(reader, meta.Size, kind)
	reader.CloseWithError(copyErr)
	download := <-done
	if copyErr != nil || download.err != nil || original == nil || uint64(original.Size()) != meta.Size || download.evidence.status != 200 || download.evidence.bytes != meta.Size || download.evidence.generation != meta.Generation || digest != meta.MD5 {
		if original != nil {
			original.Close()
		}
		return nil, [32]byte{}, ErrCorrupt
	}
	return original, sum, nil
}
