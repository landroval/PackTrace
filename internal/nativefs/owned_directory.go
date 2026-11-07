package nativefs

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
)

// OwnedDirectory is a separately constructed write capability. An ordinary
// target Root cannot be converted into it. Kernel handles never leave nativefs.
// WriteControl is exclusive and bounded; it does not publish an activation.
type OwnedDirectory struct {
	mu     sync.Mutex
	root   *Root
	native *ownedNative
	closed bool
}

func OpenOwnedDirectory(ctx context.Context, path string, createNew bool) (*OwnedDirectory, error) {
	if ctx == nil {
		return nil, ErrPath
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := openOwnedDirectory(path, createNew)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, d.Close())
	}
	return d, nil
}

// ReadRoot borrows an ordinary read capability; closing the owner invalidates it.
func (d *OwnedDirectory) ReadRoot() *Root {
	if d == nil {
		return nil
	}
	return d.root
}

func (d *OwnedDirectory) WriteControl(ctx context.Context, name string, data []byte) error {
	if d == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.root == nil || d.native == nil {
		return ErrClosed
	}
	if ctx == nil || len(data) > 4096 || !controlName(name) {
		return ErrPath
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, unlock, err := d.root.lockNative()
	if err != nil {
		return err
	}
	defer unlock()
	if err := d.native.writeControl(n, name, data); err != nil {
		return err
	}
	return ctx.Err()
}

func controlName(name string) bool {
	if len(name) == 0 || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	// Portable generated control names, not caller paths or DOS device aliases.
	for _, b := range []byte(name) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.') {
			return false
		}
	}
	if strings.HasSuffix(name, ".") {
		return false
	}
	base, _, _ := strings.Cut(name, ".")
	switch base {
	case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9":
		return false
	}
	return true
}

// The creating file handle remains retained through the current-slot check.
// Matching bytes or an equal name cannot substitute for its original inode/ID.
func ownedControlBinding(n *nativeRoot, f *os.File, name string, size int) error {
	if n == nil || f == nil || size < 0 || size > 4096 || !ownedRelative(name) {
		return ErrPath
	}
	current, err := statNative(f)
	if err != nil || current.kind() != KindRegular || current.links != 1 || current.size != int64(size) {
		return ErrUnstable
	}
	selected, bound, err := ownedControlMetadata(n, name)
	if err != nil {
		return ErrUnstable
	}
	closeErr := selected.Close()
	if closeErr != nil || bound != current {
		return ErrUnstable
	}
	return nil
}

func (d *OwnedDirectory) Close() error {
	if d == nil {
		return ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.root == nil || d.native == nil {
		return ErrClosed
	}
	d.closed = true
	return errors.Join(d.root.Close(), d.native.close())
}

// OwnedIdentity checks actual owner/protection and original binding. The digest
// is an instance selector, NOT publisher trust, separation or a secret token.
func (r *Root) OwnedIdentity(ctx context.Context) ([32]byte, error) {
	if ctx == nil {
		return [32]byte{}, ErrPath
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	n, unlock, err := r.lockNative()
	if err != nil {
		return [32]byte{}, err
	}
	defer unlock()
	if err := n.guard(); err != nil {
		return [32]byte{}, err
	}
	return ownedIdentity(n)
}
