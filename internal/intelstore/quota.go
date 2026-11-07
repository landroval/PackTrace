package intelstore

import (
	"context"
	"errors"
	"io"

	"packtrace/internal/nativefs"
)

// A zero observation is unknown, not verified empty storage. Only bounded native
// accounting under the retained writer lease can construct a complete value.
type quotaObservation struct {
	used, held uint64
	complete   bool
}

// observeQuota counts actual retained lengths without reading regular content.
// Unknown entries and failed enumeration are never a successful zero. A native
// writer lease must remain live through the complete bounded metadata walk.
func (s *Store) observeQuota(ctx context.Context, writer *nativefs.OwnedLock, limit uint64) (quotaObservation, error) {
	if s == nil || writer == nil || ctx == nil {
		return quotaObservation{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil || writer.Matches(ctx, s.root, "writer.lock", true) != nil {
		return quotaObservation{}, ErrUnavailable
	}
	var used uint64
	var visit func(string, int) error
	visit = func(name string, depth int) (failure error) {
		if depth > 128 {
			return ErrLimit
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := s.root.OpenDirectoryMetadata(ctx, name)
		if err != nil {
			return ErrUnavailable
		}
		defer func() { failure = errors.Join(failure, dir.Close()) }()
		for {
			batch, err := dir.Next()
			if err != nil && !errors.Is(err, io.EOF) {
				return ErrUnavailable
			}
			for _, entry := range batch {
				if entry.Status != nativefs.StatusComplete {
					return ErrUnavailable
				}
				switch entry.Kind {
				case nativefs.KindDirectory:
					if err := visit(entry.Name, depth+1); err != nil {
						return err
					}
				case nativefs.KindRegular:
					if entry.Size < 0 || !canReserve(used, 0, uint64(entry.Size), limit) {
						return ErrLimit
					}
					used += uint64(entry.Size)
				default:
					return ErrOwnership
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
		}
	}
	if err := visit(".", 0); err != nil {
		return quotaObservation{}, err
	}
	if err := writer.Matches(ctx, s.root, "writer.lock", true); err != nil {
		return quotaObservation{}, ErrUnavailable
	}
	return quotaObservation{used: used, complete: true}, nil
}

func canReserve(used, held, add, limit uint64) bool {
	return used <= limit && held <= limit-used && add <= limit-used-held
}

func (q quotaObservation) reserve(add, limit uint64) (quotaObservation, error) {
	if !q.complete {
		return quotaObservation{}, ErrUnavailable
	}
	if !canReserve(q.used, q.held, add, limit) {
		return quotaObservation{}, ErrLimit
	}
	q.held += add
	return q, nil
}
