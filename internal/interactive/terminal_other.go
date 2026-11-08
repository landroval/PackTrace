//go:build !linux

package interactive

import (
	"errors"
	"io"
	"os"
)

// Native UI/input restoration is not inferred from cross-compilation.
func Available(*os.File, io.Writer) bool { return false }
func Capture(*os.File, *os.File) (int, int, func() error, error) {
	return 0, 0, nil, errors.New("interactive terminal unavailable")
}
