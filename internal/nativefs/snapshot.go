package nativefs

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"
	"strings"
)

func (r *Root) Snapshot(ctx context.Context, limits Limits) (Snapshot, error) {
	return r.snapshot(ctx, limits, true, true, nil)
}

// Metadata performs bounded physical discovery without opening regular content
// or traversing directory links. Hash fields are deliberately absent.
func (r *Root) Metadata(ctx context.Context, limits Limits) (Snapshot, error) {
	return r.snapshot(ctx, limits, false, false, nil)
}

// SnapshotPruned records a boundary's metadata but does not read or traverse it.
// The predicate receives captured metadata BEFORE any content open; a pathname
// alone cannot establish the entry's type or physical ownership boundary.
// Use a captured subroot to confine links and keep physical ownership local.
func (r *Root) SnapshotPruned(ctx context.Context, limits Limits, boundary func(Entry) bool) (Snapshot, error) {
	return r.snapshot(ctx, limits, true, false, boundary)
}
func (r *Root) snapshot(ctx context.Context, limits Limits, content, followLinks bool, boundary func(Entry) bool) (Snapshot, error) {
	var s Snapshot
	l, err := normalizeLimits(limits)
	if err != nil {
		s.Reasons = []string{"limit"}
		return s, err
	}
	// The explicit root check also rejects zero/closed capabilities for empty trees.
	root, err := r.lookup(ctx, ".", true)
	if err != nil {
		s.Reasons = []string{"root-unavailable"}
		return s, err
	}
	defer root.close()
	s.Complete = true
	s.Enumerated = true
	var first error
	gap := func(reason string, err error) {
		s.Complete = false
		switch reason {
		case "canceled", "entry-limit", "depth-limit", "path-limit", "directory-unreadable", "directory-unstable":
			s.Enumerated = false
		}
		if first == nil {
			first = err
		}
		for _, old := range s.Reasons {
			if old == reason {
				return
			}
		}
		s.Reasons = append(s.Reasons, reason)
	}
	var bytes int64
	buffer := make([]byte, 32<<10)
	stack := map[[2]uint64]bool{}
	var walk func(string, *object, int)
	walk = func(base string, dir *object, depth int) {
		if err := ctx.Err(); err != nil {
			gap("canceled", err)
			return
		}
		key := [2]uint64{dir.initial.dev, dir.initial.ino}
		if stack[key] {
			gap("link-cycle", ErrPath)
			return
		}
		stack[key] = true
		defer delete(stack, key)
		for {
			// ReadDir's positive bound avoids allocating an unbounded whole directory.
			names, readErr := dir.handle.ReadDir(64)
			for _, name := range names {
				if err := ctx.Err(); err != nil {
					gap("canceled", err)
					return
				}
				if len(s.Entries) >= l.Entries {
					gap("entry-limit", ErrLimit)
					return
				}
				rel := name.Name()
				if base != "." {
					rel = base + "/" + rel
				}
				if validRelative(rel) != nil {
					gap("path-limit", ErrPath)
					continue
				}
				e := Entry{Name: rel, Status: StatusComplete}
				if depth > l.Depth {
					e.Status = StatusExcluded
					s.Entries = append(s.Entries, e)
					gap("depth-limit", ErrLimit)
					continue
				}
				o, err := r.lookupMode(ctx, rel, false, false, false)
				if err != nil {
					e.Status = StatusUnreadable
					s.Entries = append(s.Entries, e)
					gap("entry-unavailable", err)
					continue
				}
				e.Kind = o.initial.kind()
				e.Size = o.initial.size
				initial := o.initial
				pruned := boundary != nil && boundary(e)
				if pruned || (!content && e.Kind != KindDirectory) {
					if e.Kind == KindLink {
						e.LinkTarget = o.target
					}
					s.Entries = append(s.Entries, e)
					o.close()
					continue
				}
				if e.Kind == KindLink {
					e.LinkTarget = o.target
					o.close()
					if !followLinks {
						// The link object is observed, not its referent. Preserve
						// type/link drift without granting referent coverage or I/O.
						link, linkErr := r.lookupMode(ctx, rel, false, false, false)
						if linkErr != nil || link.initial != initial || link.target != e.LinkTarget {
							e.Status = StatusUnstable
							gap("link-unstable", ErrUnstable)
						}
						link.close()
						s.Entries = append(s.Entries, e)
						gap("link-not-traversed", ErrPath)
						continue
					}
					o, err = r.lookup(ctx, rel, true)
					if err != nil {
						e.Status = StatusExcluded
						s.Entries = append(s.Entries, e)
						gap("link-unresolved", err)
						continue
					}
				}
				index := len(s.Entries)
				s.Entries = append(s.Entries, e)
				switch o.initial.kind() {
				case KindRegular:
					if !content {
						break
					}
					// Link rows preserve the link itself; OpenRegular separately supports
					// reading a safe in-root link. No target-file hash masquerades as link bytes.
					if e.Kind != KindLink {
						cap := l.FileBytes
						if remain := l.TotalBytes - bytes; remain < cap {
							cap = remain
						}
						if o.initial.size > cap {
							s.Entries[index].Status = StatusExcluded
							gap("byte-limit", ErrLimit)
						} else {
							f, openErr := r.OpenRegular(ctx, rel, cap)
							if openErr != nil {
								s.Entries[index].Status = StatusUnreadable
								gap("file-unavailable", openErr)
							} else {
								h := sha256.New()
								n, copyErr := io.CopyBuffer(h, f, buffer)
								bytes += n
								stableErr := f.Stable()
								closeErr := f.Close()
								if copyErr != nil || stableErr != nil || closeErr != nil || f.initial != initial {
									s.Entries[index].Status = StatusUnstable
									gap("file-unstable", ErrUnstable)
								} else {
									copy(s.Entries[index].SHA256[:], h.Sum(nil))
								}
							}
						}
					}
				case KindDirectory:
					if stack[[2]uint64{o.initial.dev, o.initial.ino}] {
						s.Entries[index].Status = StatusExcluded
						gap("link-cycle", ErrPath)
					} else {
						walk(rel, o, depth+1)
						now, statErr := statNative(o.handle)
						if statErr != nil || now != o.initial || r.check(rel, o.initial) != nil {
							s.Entries[index].Status = StatusUnstable
							gap("directory-unstable", ErrUnstable)
						}
					}
				default:
					s.Entries[index].Status = StatusExcluded
					gap("unsupported-type", ErrType)
				}
				o.close()
				// Recheck link text/identity as well as the followed object's stability.
				if e.Kind == KindLink {
					link, linkErr := r.lookup(ctx, rel, false)
					if linkErr != nil || link.initial != initial || link.target != e.LinkTarget {
						s.Entries[index].Status = StatusUnstable
						gap("link-unstable", ErrUnstable)
					}
					link.close()
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					gap("directory-unreadable", ErrRead)
				}
				break
			}
		}
		now, err := statNative(dir.handle)
		if err != nil || now != dir.initial || r.check(base, dir.initial) != nil {
			gap("directory-unstable", ErrUnstable)
		}
	}
	walk(".", root, 1)
	s.ReadBytes = bytes
	if err := ctx.Err(); err != nil {
		gap("canceled", err)
	}
	sort.Slice(s.Entries, func(i, j int) bool { return strings.Compare(s.Entries[i].Name, s.Entries[j].Name) < 0 })
	sort.Strings(s.Reasons)
	return s, first
}
