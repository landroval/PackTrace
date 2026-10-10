package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"packtrace/internal/demo"
	"packtrace/internal/jsoninput"
)

// ReadBun validates the outer wire and the original inner JSONC separately;
// callers receive only the portable allowlist, never raw analysis or diagnostics.
func ReadBun(in io.Reader) (Result, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxWireBytes+1))
	if err != nil {
		return Result{}, errors.New("inspect-bun: read-failed")
	}
	if len(data) > maxWireBytes {
		return Result{}, errors.New("inspect-bun: limit-exceeded")
	}
	fields, code := jsoninput.Object(data, maxWireBytes)
	if code != "" || len(fields) != 2 {
		return Result{}, errors.New("inspect-bun: invalid-input")
	}
	var text string
	advisory := bytes.TrimSpace(fields["advisory"])
	if json.Unmarshal(fields["lockfile_text"], &text) != nil || text == "" || len(advisory) == 0 || advisory[0] != '{' {
		return Result{}, errors.New("inspect-bun: invalid-input")
	}
	raw, err := demo.EvaluateBunMetadata([]byte(text), advisory)
	if err != nil {
		return Result{}, errors.New("inspect-bun: invalid-metadata")
	}
	return portableResult(raw, "packtrace.inspect.bun.v1"), nil
}
