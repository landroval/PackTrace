package nativefs

import (
	"context"
	"sync"
)

// PublicationPlan retains read-only original source and destination admission.
// Source roots are borrowed and must outlive the plan. It is not a generation
// pin, authentication token, or transferable OS authority.
type PublicationPlan struct {
	mu               sync.Mutex
	publication      *Publication
	begun, fulfilled bool
}

func OpenPublicationPlan(ctx context.Context, target *Root, additional []*Root, destination string) (*PublicationPlan, error) {
	if target == nil || target.anchor != nil || len(additional) > maxPublicationExclusions {
		return nil, ErrPath
	}
	seen := map[*Root]bool{target: true}
	for _, r := range additional {
		if r == nil || seen[r] || r.anchor != target {
			return nil, ErrPath
		}
		seen[r] = true
	}
	if e := publicationPlanAvailable(); e != nil {
		return nil, e
	}
	p, e := capturePublication(ctx, target, destination, additional)
	if e != nil {
		return nil, e
	}
	p.retained = true
	plan := &PublicationPlan{publication: p}
	if _, e = plan.Binding(); e != nil {
		plan.Close()
		return nil, e
	}
	return plan, nil
}

// Binding validates the entire retained plan and returns a native continuity
// receipt. It is only available before Begin/Fulfill.
func (p *PublicationPlan) Binding() (string, error) {
	if p == nil {
		return "", ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publication == nil || p.begun || p.fulfilled {
		return "", ErrClosed
	}
	return publicationPlanBinding(p.publication)
}
func (p *PublicationPlan) Check() error { _, e := p.Binding(); return e }

// CheckSources deliberately does not inspect output branch stamps: a confirmed
// writer has mutated that branch. Every original source proof remains retained.
func (p *PublicationPlan) CheckSources() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publication == nil {
		return ErrClosed
	}
	p.publication.mu.Lock()
	defer p.publication.mu.Unlock()
	return publicationPlanSources(p.publication)
}

// Fulfill is called only after the caller observes writer ack AND actual reap.
// It does not infer those transport facts from filesystem state.
func (p *PublicationPlan) Fulfill() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publication == nil || p.fulfilled {
		return ErrClosed
	}
	p.publication.mu.Lock()
	defer p.publication.mu.Unlock()
	if p.publication.file != nil {
		return ErrUnstable
	}
	if e := publicationPlanSources(p.publication); e != nil {
		return e
	}
	p.fulfilled = true
	return nil
}

// Begin creates through the already retained parent, without reopening paths.
// Even a failed Begin consumes this plan; uncertain residues are never removed.
func (p *PublicationPlan) Begin() (*Publication, error) {
	if p == nil {
		return nil, ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publication == nil || p.begun || p.fulfilled {
		return nil, ErrClosed
	}
	p.begun = true
	if _, e := publicationPlanBinding(p.publication); e != nil {
		return nil, e
	}
	if e := p.publication.begin(); e != nil {
		return nil, e
	}
	return p.publication, nil
}
func (p *PublicationPlan) Close() error {
	if p == nil {
		return ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publication == nil {
		return nil
	}
	q := p.publication
	q.mu.Lock()
	defer q.mu.Unlock()
	// Never invalidate a still-live publication's original proofs.
	if q.file != nil {
		return ErrUnstable
	}
	p.publication = nil
	return q.closeProofs()
}
