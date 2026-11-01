package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

var errCapture = errors.New("capture-limit")

// Windows x64-on-Arm has no WOW64 layer: its WOW64 machine value may be
// UNKNOWN. Use the running Go program's compiled ISA and the successfully
// queried native host, never promote UNKNOWN into an ISA measurement.
// https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation
func desktopEmulation(compiledArch string, host uint16) bool {
	return compiledArch == "amd64" && host == 0xaa64
}

func volumeDiagnostic(profile string) (bool, error) {
	switch profile {
	case "windows-scan-amd64-v1", "windows11-x64-compat-arm64-v1":
		return false, nil
	case "windows-volume-diagnostic-amd64-v1":
		return true, nil
	default:
		return false, errors.New("unsupported-native-profile")
	}
}

type capture struct {
	mu       sync.Mutex
	data     []byte
	cap      int
	complete bool
	stop     func()
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := min(len(p), c.cap-len(c.data))
	c.data = append(c.data, p[:n]...)
	if n < len(p) {
		c.complete = false
		c.stop()
		return n, errCapture
	}
	return len(p), nil
}

type counts struct{ Passed, Failed, Skipped, BuildFailed int }

func testCounts(data []byte) (counts, error) {
	var c counts
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var event struct{ Action, Test string }
		if e := json.Unmarshal(scan.Bytes(), &event); e != nil {
			return c, e
		}
		switch event.Action {
		case "pass":
			if event.Test != "" {
				c.Passed++
			}
		case "skip":
			if event.Test != "" {
				c.Skipped++
			}
		case "fail":
			c.Failed++
		case "build-fail":
			c.BuildFailed++
		}
	}
	if e := scan.Err(); e != nil {
		return c, e
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || c.Passed == 0 {
		return c, io.ErrUnexpectedEOF
	}
	return c, nil
}
