//go:build !windows

package execution

import (
	"io"
	"os"
)

func platformPipe() (*os.File, *os.File, error) { return os.Pipe() }

func platformControlInput(in io.Reader) (io.Reader, func(), error) {
	return in, func() {}, nil
}
