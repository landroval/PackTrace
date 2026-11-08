package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/interactive"
)

type interactiveConfig struct {
	Nonce                              string
	Size                               int
	SHA256                             string
	Width, Height, Milliseconds, Limit int
	Color                              bool
}
type interactiveDone struct {
	Size        int
	SHA256      string
	Rendered    int
	Interrupted bool
}

// Same sequential, observed/reaped output role; no direct parent terminal writes
// and no parser-chosen public bytes. Original source leases remain held throughout.
func (r *ScanRun) WriteInteractive(ctx context.Context, in, out *os.File, view cli.InteractiveView, color bool) (interrupted bool, failure error) {
	if r.Checkpoint() != nil || cli.ValidateInteractiveView(view) != nil {
		return false, errOutput
	}
	w, h, restore, e := interactive.Capture(in, out)
	if e != nil {
		return false, errOutput
	}
	defer func() {
		if restore() != nil {
			failure = errOutput
		}
		if e := r.Checkpoint(); e != nil && failure == nil {
			failure = e
		}
	}()
	raw, e := json.Marshal(view)
	if e != nil || len(raw) > cli.MaxInteractiveBytes {
		return false, errLimit
	}
	s := r.output.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.contextError(ctx) != nil || s.broken {
		return false, errOutput
	}
	if e = s.budget.add(len(raw)); e != nil {
		return false, e
	}
	s.budget.mu.Lock()
	limit := min(8<<20, maxTraffic-s.budget.n-(16<<10))
	s.budget.mu.Unlock()
	if limit < 1 {
		return false, errLimit
	}
	cmd, e := childCommand(WriterArgument)
	if e != nil {
		return false, e
	}
	identity, e := buildIdentity()
	if e != nil {
		return false, e
	}
	dataIn, dataOut, e := privatePipe()
	if e != nil {
		return false, e
	}
	defer dataIn.Close()
	defer dataOut.Close()
	nonce, release, e := configureLaunch(cmd, "scan-ui", out, dataIn, in)
	if e != nil {
		return false, e
	}
	sum := sha256.Sum256(raw)
	cfg := interactiveConfig{nonce, len(raw), hex.EncodeToString(sum[:]), w, h, int(time.Until(s.deadline) / time.Millisecond), limit, color}
	if cfg.Milliseconds < 1 {
		release()
		return false, errOutput
	}
	received := false
	failure = s.runChild(ctx, cmd, release, func(work context.Context, c *channel, input io.Closer) error {
		joined := make(chan struct{})
		stop := context.AfterFunc(work, func() { defer close(joined); _ = dataOut.Close() })
		defer func() {
			if !stop() {
				<-joined
			}
		}()
		var helloValue hello
		if c.expect("hello", &helloValue) != nil || helloValue.Build != identity {
			return errProtocol
		}
		if c.send("hello", hello{identity}) != nil || c.send("interactive", cfg) != nil || input.Close() != nil {
			return errProtocol
		}
		if n, e := dataOut.Write(raw); e != nil || n != len(raw) {
			return errOutput
		}
		if dataOut.Close() != nil {
			return errOutput
		}
		var done interactiveDone
		if c.expect("viewed", &done) != nil || done.Size != cfg.Size || done.SHA256 != cfg.SHA256 || done.Rendered <= 0 || done.Rendered > limit {
			return errProtocol
		}
		if e = s.budget.add(done.Rendered); e != nil {
			return e
		}
		received = true
		interrupted = done.Interrupted
		if _, e = c.receive(); e != io.EOF {
			return errProtocol
		}
		return nil
	})
	if !received {
		_ = s.budget.add(limit)
	} // Failed output remains conservatively charged.
	r.NoteFailure("output", failure)
	return interrupted, failure
}

func interactiveWriterMain(in io.Reader, out io.Writer) int {
	nonce, ids, e := launchCapability("scan-ui")
	if e != nil || len(ids) != 3 {
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
	c := newChannel(in, out, &traffic{})
	if c.send("hello", hello{identity}) != nil {
		return 2
	}
	var h hello
	if c.expect("hello", &h) != nil || h.Build != identity {
		return 2
	}
	var cfg interactiveConfig
	if c.expect("interactive", &cfg) != nil || cfg.Nonce != nonce || cfg.Size < 0 || cfg.Size > cli.MaxInteractiveBytes || cfg.Limit < 1 || cfg.Limit > 8<<20 || cfg.Width < 40 || cfg.Width > 180 || cfg.Height < 12 || cfg.Height > 60 || cfg.Milliseconds < 1 || cfg.Milliseconds > 300000 {
		return 2
	}
	if _, e = c.receive(); e != io.EOF {
		return 2
	}
	data := os.NewFile(ids[1], "approved-interactive-view")
	public := os.NewFile(ids[0], "original-interactive-output")
	keyboard := os.NewFile(ids[2], "original-interactive-input")
	if data == nil || public == nil || keyboard == nil {
		return 2
	}
	defer data.Close()
	defer public.Close()
	defer keyboard.Close()
	raw, e := io.ReadAll(io.LimitReader(data, int64(cfg.Size)+1))
	if e != nil || len(raw) != cfg.Size {
		return 2
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != cfg.SHA256 {
		return 2
	}
	var view cli.InteractiveView
	if json.Unmarshal(raw, &view) != nil || cli.ValidateInteractiveView(view) != nil || !interactive.Available(keyboard, public) {
		return 2
	}
	interrupted, n, e := interactive.Run(keyboard, public, view, cfg.Width, cfg.Height, cfg.Color, cfg.Milliseconds, cfg.Limit)
	if e != nil {
		return 2
	}
	if c.send("viewed", interactiveDone{cfg.Size, cfg.SHA256, n, interrupted}) != nil {
		return 2
	}
	return 0
}
