package intelstore

import (
	"context"
	"io"
	"packtrace/internal/nativefs"
	"sync"
)

// archiveCache captures bounded immutable windows from the ORIGINAL owned
// source. Every actual native read still uses its complete native guards and
// shared I/O budget. Cached bytes are not new filesystem observations. Stable
// on that original is mandatory before any generation/source publication.
type archiveCache struct {
	mu       sync.Mutex
	ctx      context.Context
	original *nativefs.OwnedFile
	buffer   []byte
	start    [2]int64
	valid    [2]int
	recent   int // Two half-MiB windows retain alternating central/local ZIP data.
	size     int64
	captured uint64
	failure  error
}

func newArchiveCache(ctx context.Context, original *nativefs.OwnedFile) (*archiveCache, error) {
	if ctx == nil || original == nil {
		return nil, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := original.Stable(); e != nil {
		return nil, e
	}
	size := original.Size()
	if size < 0 || size > 1<<30 {
		return nil, ErrLimit
	}
	return &archiveCache{ctx: ctx, original: original, buffer: make([]byte, 1<<20), size: size}, nil
}
func (c *archiveCache) ReadAt(p []byte, off int64) (n int, failure error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return 0, c.failure
	}
	if e := c.ctx.Err(); e != nil {
		c.failure = e
		return 0, e
	}
	if off < 0 {
		return 0, ErrCorrupt
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= c.size {
		return 0, io.EOF
	}
	originalLength := len(p)
	if int64(len(p)) > c.size-off {
		p = p[:int(c.size-off)]
	}
	for n < len(p) {
		at := off + int64(n)
		slot := -1
		for i := range c.start {
			if at >= c.start[i] && at < c.start[i]+int64(c.valid[i]) {
				slot = i
				break
			}
		}
		window := len(c.buffer) / 2
		if slot < 0 {
			slot = 1 - c.recent
			if e := c.ctx.Err(); e != nil {
				c.failure = e
				return n, e
			}
			start := at / int64(window) * int64(window)
			want := int64(window)
			if want > c.size-start {
				want = c.size - start
			}
			if uint64(want) > (8<<30)-c.captured {
				c.failure = ErrLimit
				return n, c.failure
			}
			c.captured += uint64(want)
			c.start[slot], c.valid[slot] = start, 0
			read, e := c.original.ReadAt(c.buffer[slot*window:slot*window+int(want)], start)
			if read != int(want) || e != nil && e != io.EOF {
				c.failure = ErrCorrupt
				return n, c.failure
			}
			c.valid[slot] = read
		}
		c.recent = slot
		within := int(at - c.start[slot])
		n += copy(p[n:], c.buffer[slot*window+within:slot*window+c.valid[slot]])
	}
	if n < originalLength {
		return n, io.EOF
	}
	return n, nil
}
func (c *archiveCache) Stable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	if e := c.ctx.Err(); e != nil {
		return e
	}
	return c.original.Stable()
}
