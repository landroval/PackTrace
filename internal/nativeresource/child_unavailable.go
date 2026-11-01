//go:build !(linux && (amd64 || arm64)) && !(darwin && cgo && (amd64 || arm64))

package nativeresource

import "errors"

var ErrUnavailable = errors.New("scan: retained-resident-query-unavailable")

// Other platforms have no retained-child RSS binding here. Do not mistake
// compilation of this refusal backend for native support or qualification.
type Child struct{}

func PinChild(pid int) (*Child, error)       { return nil, ErrUnavailable }
func (*Child) Sample() (uint64, bool, error) { return 0, false, ErrUnavailable }
func (*Child) Close() error                  { return nil }
