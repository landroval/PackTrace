package intelstore

import (
	"context"
	"errors"
)

// Full preparation may reconcile changes through the existing reuse path. That
// path cannot inherit proof. Only this explicit full operation reparses its final
// actual originals and requires exact catalog/index/slot equality before v2.
func rebuildFullConstruction(ctx context.Context, t *Transaction, draft generationDraft) (generationDraft, error) {
	prep := t.prep.record
	ids, err := t.store.objectReader(ctx, prep.SourceIDs)
	if err != nil {
		return generationDraft{}, err
	}
	defer ids.Close()
	cursor := newSourceIDCursor(ids)
	t.prep = &preparationState{record: newPreparation(2)}
	for ordinal := uint64(0); ordinal < prep.Records; ordinal++ {
		row, err := cursor.next()
		if err != nil || row == nil {
			return generationDraft{}, ErrCorrupt
		}
		raw, err := t.existingAdvisory(ctx, row.Original)
		if err != nil {
			return generationDraft{}, err
		}
		forced := sourceObserved
		if row.Disposition == sourceUnresolved {
			forced = sourceUnresolved
		}
		if err := prepareOriginal(ctx, t, row.ID, raw, &row.Original, forced); err != nil {
			return generationDraft{}, err
		}
	}
	if row, err := cursor.next(); err != nil || row != nil {
		return generationDraft{}, ErrCorrupt
	}
	if err := ids.Close(); err != nil {
		return generationDraft{}, err
	}
	rebuilt, err := buildIndexes(ctx, t)
	if err != nil {
		return generationDraft{}, err
	}
	if rebuilt.Manifest != draft.Manifest {
		return generationDraft{}, errors.New("intel: full construction index mismatch")
	}
	rebuilt.Cursor = draft.Cursor
	rebuilt.Objects = append(rebuilt.Objects, draft.Objects...)
	return rebuilt, nil
}
