package intelstore

import (
	"context"
	"packtrace/internal/nativefs"
)

// OpenReportPlan retains read-only admission using the original private store
// root. Caller retains this store and its original generation Pin/PhysicalBinding
// through acquisition, writer reap and Finish; this plan does not replace them.
func (s *Store) OpenReportPlan(ctx context.Context, target *nativefs.Root, references []*nativefs.Root, destination string) (*nativefs.PublicationPlan, error) {
	if s == nil {
		return nil, ErrBinding
	}
	if len(references) > 7 {
		return nil, ErrLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil || s.mode != ReadOnly {
		return nil, ErrBinding
	}
	exclusions := make([]*nativefs.Root, 0, len(references)+1)
	exclusions = append(exclusions, s.root)
	exclusions = append(exclusions, references...)
	return nativefs.OpenPublicationPlan(ctx, target, exclusions, destination)
}

// OpenReportPublication grants only target-bound no-clobber report publication
// outside the original target, original store and supplied reference roots.
// It never exports a store Root or permits writes through an ordinary Root.
// This is a native capability, not a scan writer transport. In a scan, the
// entire constructor/write/commit/close sequence belongs in the observed,
// terminable output worker, never synchronously in the supervisor.
// The caller must retain the store, target, references and generation pin until
// publication closes (and, across process use, until actual worker reap).
func (s *Store) OpenReportPublication(ctx context.Context, target *nativefs.Root, references []*nativefs.Root, destination string) (*nativefs.Publication, error) {
	if s == nil {
		return nil, ErrBinding
	}
	// Native publication admits eight additional exclusions, including store.
	if len(references) > 7 {
		return nil, ErrLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil || s.mode != ReadOnly {
		return nil, ErrBinding
	}
	exclusions := make([]*nativefs.Root, 0, len(references)+1)
	exclusions = append(exclusions, s.root)
	exclusions = append(exclusions, references...)
	return nativefs.OpenPublicationExcluding(ctx, target, exclusions, destination)
}
