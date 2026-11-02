package intelstore

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"packtrace/internal/intel"
	"sort"
	"strings"
)

type preparationRecord struct {
	Version                                                int    `json:"version"`
	Source                                                 string `json:"source"`
	Records, Memberships, IdentityGaps, OutsideNPM         uint64
	SourceIDs                                              ObjectRef
	GitHubRecords, OpenSSFRecords, UnknownPublisherRecords uint64
}
type preparationState struct {
	cat, idLines    bytes.Buffer
	rows            []indexRow
	buffered        uint64
	catRuns, idRuns []ObjectRef
	runs            [256][]ObjectRef
	counts          [256]uint64
	record          preparationRecord
}
type sourceIDRow struct {
	ID, Modified string
	Original     ObjectRef
}
type indexRow struct {
	V              int    `json:"v"`
	IdentityHash   string `json:"identityHash"`
	Ecosystem      string `json:"ecosystem"`
	Name           string `json:"name"`
	SourceOrdinal  uint64 `json:"sourceOrdinal"`
	OriginalSHA256 string `json:"originalSHA256"`
	OriginalBytes  uint64 `json:"originalBytes"`
	AffectedIndex  uint64 `json:"affectedIndex"`
}

func publicRecordID(id string) bool {
	if len(id) == 0 || len(id) > 240 {
		return false
	}
	for i, c := range []byte(id) {
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !letter && (i == 0 || i == len(id)-1 || c != '-' && c != '_' && c != '.') {
			return false
		}
	}
	return true
}
func prepareArchive(ctx context.Context, t *Transaction, input io.ReaderAt, size int64) (result generationDraft, failure error) {
	defer func() {
		if failure != nil && t != nil {
			t.mu.Lock()
			t.failed = failure
			t.mu.Unlock()
		}
	}()
	if t == nil || ctx == nil || input == nil || size < 0 || size > 1<<30 {
		return generationDraft{}, ErrLimit
	}
	if t.prep != nil {
		return generationDraft{}, ErrCorrupt
	}
	archive, e := zip.NewReader(input, size)
	if e != nil {
		return generationDraft{}, ErrCorrupt
	}
	if len(archive.File) == 0 || len(archive.File) > 2_000_000 {
		return generationDraft{}, ErrLimit
	}
	if e := validateZIPStructure(input, size, archive.File); e != nil {
		return generationDraft{}, e
	}
	files := append([]*zip.File(nil), archive.File...)
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") || strings.ContainsAny(f.Name, "/\\") || !publicRecordID(strings.TrimSuffix(f.Name, ".json")) || !f.Mode().IsRegular() || f.Flags&1 != 0 || f.Method != zip.Store && f.Method != zip.Deflate {
			return generationDraft{}, ErrCorrupt
		}
		key := strings.ToLower(f.Name)
		if seen[key] {
			return generationDraft{}, ErrCorrupt
		}
		seen[key] = true
		offset, e := f.DataOffset()
		if e != nil || offset < 0 || offset > size || f.CompressedSize64 > uint64(size-offset) || f.UncompressedSize64 > 4<<20 {
			return generationDraft{}, ErrLimit
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	p := &preparationState{record: preparationRecord{Version: 1, Source: "caller-supplied"}}
	t.prep = p
	var expanded uint64
	for ordinal, f := range files {
		if e := ctx.Err(); e != nil {
			return generationDraft{}, e
		}
		if e := t.work.Err(); e != nil {
			return generationDraft{}, e
		}
		r, e := f.Open()
		if e != nil {
			return generationDraft{}, ErrCorrupt
		}
		raw, readErr := io.ReadAll(io.LimitReader(r, (4<<20)+1))
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || len(raw) > 4<<20 || uint64(len(raw)) != f.UncompressedSize64 {
			return generationDraft{}, ErrCorrupt
		}
		if uint64(len(raw)) > 8<<30-expanded {
			return generationDraft{}, ErrLimit
		}
		expanded += uint64(len(raw))
		doc, e := intel.ParseOSVRecord(raw)
		if e != nil {
			return generationDraft{}, ErrCorrupt
		}
		header, e := intel.ProjectOSVHeader(doc)
		if e != nil || header.ID.Value != strings.TrimSuffix(f.Name, ".json") || header.Schema != intel.OSVHeaderSchemaV1Implicit && header.Schema != intel.OSVHeaderSchemaV1Declared {
			return generationDraft{}, ErrCorrupt
		}
		affected, e := intel.ProjectOSVAffected(doc)
		if e != nil {
			return generationDraft{}, ErrCorrupt
		}
		identities, e := intel.QualifyOSVNPMIdentities(header, affected)
		if e != nil {
			return generationDraft{}, ErrCorrupt
		}
		ref, e := t.put(ctx, bytes.NewReader(raw), uint64(len(raw)))
		if e != nil {
			return generationDraft{}, e
		}
		p.record.Records++
		switch {
		case strings.HasPrefix(header.ID.Value, "GHSA-"):
			p.record.GitHubRecords++
		case strings.HasPrefix(header.ID.Value, "MAL-"):
			p.record.OpenSSFRecords++
		default:
			p.record.UnknownPublisherRecords++
		}
		catalog, _ := json.Marshal(struct {
			V       int    `json:"v"`
			Ordinal uint64 `json:"sourceOrdinal"`
			SHA     string `json:"sha256"`
			Bytes   uint64 `json:"bytes"`
		}{1, uint64(ordinal), hex.EncodeToString(ref.SHA256[:]), ref.Bytes})
		p.cat.Write(catalog)
		p.cat.WriteByte('\n')
		p.buffered += uint64(len(catalog) + 1)
		var modified string
		_ = json.Unmarshal(doc.Fields["modified"], &modified)
		idLine, _ := json.Marshal(sourceIDRow{header.ID.Value, modified, ref})
		p.idLines.Write(idLine)
		p.idLines.WriteByte('\n')
		p.buffered += uint64(len(idLine) + 1)
		if identities.State != intel.OSVFieldValue {
			p.record.IdentityGaps++
		}
		for _, identity := range identities.Entries {
			if identity.Ecosystem.State == intel.OSVFieldValue && identity.Ecosystem.Value != "npm" {
				p.record.OutsideNPM++
				continue
			}
			if identity.Qualification != intel.OSVNPMIdentityCandidate {
				p.record.IdentityGaps++
				continue
			}
			hash := sha256.Sum256(append([]byte("npm\x00"), []byte(identity.Name.Value)...))
			row := indexRow{1, hex.EncodeToString(hash[:]), "npm", identity.Name.Value, uint64(ordinal), hex.EncodeToString(ref.SHA256[:]), ref.Bytes, uint64(identity.Index)}
			if e := p.admitRow(row); e != nil {
				return generationDraft{}, e
			}
		}
		if p.buffered >= 64<<20 {
			if e := p.flush(ctx, t); e != nil {
				return generationDraft{}, e
			}
		}
	}
	return buildIndexes(ctx, t)
}
func (p *preparationState) admitRow(row indexRow) error {
	if p.record.Memberships >= 2_000_000 {
		return ErrLimit
	}
	hash, err := hex.DecodeString(row.IdentityHash)
	if err != nil || len(hash) != 32 {
		return ErrCorrupt
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return ErrCorrupt
	}
	p.rows = append(p.rows, row)
	p.buffered += uint64(len(encoded) + 128)
	p.counts[hash[0]]++
	p.record.Memberships++
	return nil
}

func (p *preparationState) flush(ctx context.Context, t *Transaction) error {
	for _, item := range []struct {
		buffer *bytes.Buffer
		runs   *[]ObjectRef
	}{{&p.cat, &p.catRuns}, {&p.idLines, &p.idRuns}} {
		if item.buffer.Len() != 0 {
			ref, e := t.put(ctx, bytes.NewReader(item.buffer.Bytes()), uint64(item.buffer.Len()))
			if e != nil {
				return e
			}
			*item.runs = append(*item.runs, ref)
			item.buffer.Reset()
		}
	}
	sort.Slice(p.rows, func(i, j int) bool { return rowLess(p.rows[i], p.rows[j]) })
	for start := 0; start < len(p.rows); {
		indexBytes, _ := hex.DecodeString(p.rows[start].IdentityHash[:2])
		partition := indexBytes[0]
		end := start
		var data bytes.Buffer
		for end < len(p.rows) && p.rows[end].IdentityHash[:2] == p.rows[start].IdentityHash[:2] {
			encoded, _ := json.Marshal(p.rows[end])
			data.Write(encoded)
			data.WriteByte('\n')
			end++
		}
		ref, e := t.put(ctx, bytes.NewReader(data.Bytes()), uint64(data.Len()))
		if e != nil {
			return e
		}
		p.runs[partition] = append(p.runs[partition], ref)
		start = end
	}
	p.rows = nil
	p.buffered = 0
	return nil
}
func rowLess(a, b indexRow) bool {
	if a.IdentityHash != b.IdentityHash {
		return a.IdentityHash < b.IdentityHash
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.SourceOrdinal != b.SourceOrdinal {
		return a.SourceOrdinal < b.SourceOrdinal
	}
	return a.AffectedIndex < b.AffectedIndex
}
