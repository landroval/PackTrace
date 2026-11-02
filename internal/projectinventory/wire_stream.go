package projectinventory

// AppendBatch enforces finite homogeneous sections and monotone section order.
// The caller owns exact sequence/closure state; ValidatePublic checks the closed
// aggregate before it can be published. Counts are never taken from a batch.
func AppendBatch(p *PublicInventory, b InventoryBatch) error {
	if p == nil {
		return ErrWire
	}
	last := -1
	for i, n := range []int{len(p.Scopes), len(p.Evidence), len(p.Observations), len(p.Relations), len(p.Gaps)} {
		if n > 0 {
			last = i
		}
	}
	kind := -1
	for i, n := range []int{len(b.Scopes), len(b.Evidence), len(b.Observations), len(b.Relations), len(b.Gaps)} {
		if n > 0 {
			if kind != -1 || n > 128 {
				return ErrWire
			}
			kind = i
		}
	}
	if kind < 0 || kind < last {
		return ErrWire
	}
	if len(p.Scopes)+len(b.Scopes) > maxRecords+1 || len(p.Evidence)+len(b.Evidence) > 100000 || len(p.Observations)+len(b.Observations) > 3*maxRecords || len(p.Relations)+len(b.Relations) > maxRecords || len(p.Gaps)+len(b.Gaps) > 257 {
		return ErrWire
	}
	p.Scopes = append(p.Scopes, b.Scopes...)
	p.Evidence = append(p.Evidence, b.Evidence...)
	p.Observations = append(p.Observations, b.Observations...)
	p.Relations = append(p.Relations, b.Relations...)
	p.Gaps = append(p.Gaps, b.Gaps...)
	return nil
}
