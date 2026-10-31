//go:build !linux || (!amd64 && !arm64)

package nativefs

import "os"

// Explicitly unavailable candidates, NOT platform support. In particular,
// Darwin must not turn a plausible Seatbelt profile into an unsafe open before
// its pre-driver hook semantics/SDK contract are established. This guard runs
// before inspecting any target path. There is no lstat/open or clone fallback.
type nativeRoot struct{}

func prepareNative() error                                               { return ErrUnavailable }
func openNativeRoot(string) (*nativeRoot, error)                         { return nil, ErrUnavailable }
func (*nativeRoot) close() error                                         { return ErrUnavailable }
func (*nativeRoot) lookup(string, bool) (*object, error)                 { return nil, ErrUnavailable }
func (*nativeRoot) check(string, stamp) error                            { return ErrUnavailable }
func statNative(*os.File) (stamp, error)                                 { return stamp{}, ErrUnavailable }
func (*nativeRoot) bindExternal(*nativeRoot) error                       { return ErrUnavailable }
func (*nativeRoot) subroot(string) (*nativeRoot, error)                  { return nil, ErrUnavailable }
func (*nativeRoot) lookupMode(string, bool, bool, bool) (*object, error) { return nil, ErrUnavailable }
func (*nativeRoot) validateRead(*os.File, stamp, bool) error             { return ErrUnavailable }
