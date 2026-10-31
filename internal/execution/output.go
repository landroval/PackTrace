package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"strings"
)

// WriteOutput transfers only parent-approved rendered bytes. The parser has
// already been reaped. Real public files are written exclusively in a second,
// sequential, same-executable process; backpressure never pins a parent thread.
func (r *BatchRun) WriteOutput(ctx context.Context, out io.Writer, data []byte) error {
	if r.state == nil {
		r.state = newRunState(ctx)
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if explicitCancel(ctx) || explicitCancel(s.caller) {
		r.Interrupted = true
	}
	if e := s.contextError(ctx); e != nil {
		return e
	}
	if s.broken {
		return errReap
	}
	if len(data) > maxTraffic {
		return errLimit
	}
	if e := s.budget.add(len(data)); e != nil {
		return e
	}
	// Only these known nonblocking memory sinks have a synchronous compatibility
	// path. Never invoke arbitrary Writer code or attempt public-file fallback.
	switch out.(type) {
	case *bytes.Buffer, *strings.Builder:
		if reflect.ValueOf(out).IsNil() {
			return errOutput
		}
		n, e := out.Write(data)
		if e != nil || n != len(data) {
			return errOutput
		}
		return nil
	}
	if out == io.Discard {
		return nil
	}
	file, ok := out.(*os.File)
	if !ok || file == nil {
		return errOutput
	}
	cmd, e := childCommand(WriterArgument)
	if e != nil {
		return errOutput
	}
	identity, e := buildIdentity()
	if e != nil {
		return errOutput
	}
	dataIn, dataOut, e := privatePipe()
	if e != nil {
		return e
	}
	defer dataIn.Close()
	defer dataOut.Close()
	cap, release, e := configureLaunch(cmd, "writer", file, dataIn)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(data)
	cfg := writerConfig{Nonce: cap, Size: len(data), SHA256: hex.EncodeToString(sum[:])}
	// Preflight all fixed writer traffic before launch. Both directions and every
	// LF are still charged by the actual channel; no rendered length from worker.
	if e = writerTrafficFits(&s.budget, identity, cfg); e != nil {
		release()
		return e
	}
	e = s.runChild(ctx, cmd, release, func(childCtx context.Context, c *channel, input io.Closer) error {
		// Private data write is deadline-checked and Close-unblocked on cancellation.
		joined := make(chan struct{})
		stop := context.AfterFunc(childCtx, func() { defer close(joined); _ = dataOut.Close() })
		defer func() {
			if !stop() {
				<-joined
			}
		}()
		var h hello
		if e := c.expect("hello", &h); e != nil || h.Build != identity {
			return errProtocol
		}
		if e := c.send("hello", hello{identity}); e != nil {
			return e
		}
		if e := c.send("config", cfg); e != nil {
			return e
		}
		if e := input.Close(); e != nil {
			return errProtocol
		}
		if n, e := dataOut.Write(data); e != nil || n != len(data) {
			return errOutput
		}
		if e := dataOut.Close(); e != nil {
			return errProtocol
		}
		var d writerDone
		if e := c.expect("written", &d); e != nil || d.Size != cfg.Size || d.SHA256 != cfg.SHA256 {
			return errOutput
		}
		if _, e := c.receive(); e != io.EOF {
			return errProtocol
		}
		return nil
	})
	if explicitCancel(ctx) || explicitCancel(s.caller) {
		r.Interrupted = true
	}
	if e != nil {
		if s.broken || s.contextError(ctx) != nil || e == errLimit {
			return e
		}
		return errOutput
	}
	return nil
}

// Compute encoded sizes without allocating/serializing the rendered bytes into
// control JSONL. This is a preflight, not a second charge against the budget.
func writerTrafficFits(b *traffic, identity string, cfg writerConfig) error {
	var sink bytes.Buffer
	c := newChannel(strings.NewReader(""), &sink, &traffic{})
	if c.send("hello", hello{identity}) != nil || c.send("config", cfg) != nil {
		return errLimit
	}
	n := sink.Len()
	sink.Reset()
	c = newChannel(strings.NewReader(""), &sink, &traffic{})
	if c.send("hello", hello{identity}) != nil || c.send("written", writerDone{cfg.Size, cfg.SHA256}) != nil {
		return errLimit
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n+sink.Len() > maxTraffic-b.n {
		return errLimit
	}
	return nil
}

// WriterMain never parses target data or selects rendering/privacy/public exit.
// Validate the COMPLETE bounded transfer/hash/EOF before touching public output.
func WriterMain(in io.Reader, out io.Writer, diagnosticOut io.Writer) int {
	cap, ids, e := launchCapability("writer")
	if e != nil {
		return 2
	}
	in, release, e := platformControlInput(in)
	if e != nil {
		return 2
	}
	defer release()
	identity, e := buildIdentity()
	if e != nil {
		return 2
	}
	budget := &traffic{}
	c := newChannel(in, out, budget)
	if c.send("hello", hello{identity}) != nil {
		return 2
	}
	var h hello
	if c.expect("hello", &h) != nil || h.Build != identity {
		return 2
	}
	var cfg writerConfig
	if c.expect("config", &cfg) != nil || cfg.Nonce != cap || cfg.Size < 0 || cfg.Size > maxTraffic {
		return 2
	}
	decoded, e := hex.DecodeString(cfg.SHA256)
	if e != nil || len(decoded) != sha256.Size {
		return 2
	}
	if _, e = c.receive(); e != io.EOF {
		return 2
	}
	if budget.add(cfg.Size) != nil {
		return 2
	}
	raw := os.NewFile(ids[1], "inspect-batch-approved-data")
	if raw == nil {
		return 2
	}
	defer raw.Close()
	data, e := io.ReadAll(io.LimitReader(raw, int64(cfg.Size)+1))
	if e != nil || len(data) != cfg.Size {
		return 2
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != cfg.SHA256 {
		return 2
	}
	public := os.NewFile(ids[0], "inspect-batch-original-output")
	if public == nil {
		return 2
	}
	defer public.Close()
	if n, e := public.Write(data); e != nil || n != len(data) {
		return 2
	}
	if c.send("written", writerDone{cfg.Size, cfg.SHA256}) != nil {
		return 2
	}
	return 0
}
