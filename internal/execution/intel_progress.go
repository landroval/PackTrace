package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"time"

	"packtrace/internal/cli"
)

const maxProgressBytes = 512 << 10

type progressConfig struct {
	Nonce  string
	Size   int
	SHA256 string
}
type progressDone struct {
	Size     int
	SHA256   string
	Rendered int
}
type intelProgress struct {
	stop   chan struct{}
	done   chan error
	cancel context.CancelFunc
}

func progressFrames(action cli.ArgumentAction) []byte {
	label := ""
	switch action {
	case cli.ArgumentActionIntelSync:
		label = "Syncing security advisory database"
	case cli.ArgumentActionIntelImport:
		label = "Importing security advisory database"
	case cli.ArgumentActionIntelExport:
		label = "Exporting security advisory database"
	default:
		return nil
	}
	frames := make([]string, 0, 5)
	for _, glyph := range "|/-\\" {
		frames = append(frames, "\r"+string(glyph)+" "+label+" (Ctrl+C to cancel)\x1b[K")
	}
	frames = append(frames, "\r\x1b[K")
	return []byte(strings.Join(frames, "\n"))
}

// The parser never gets a public descriptor. A separate bounded writer receives
// only parent-approved frames; its actual PID shares the parser's observer,
// absolute deadline, traffic budget, and aggregate 1 GiB resident limit.
func startIntelProgress(ctx context.Context, s *runState, out *os.File, action cli.ArgumentAction, failed context.CancelFunc) (*intelProgress, error) {
	data := progressFrames(action)
	if len(data) == 0 || out == nil {
		return nil, errOutput
	}
	if e := s.budget.add(len(data) + maxProgressBytes); e != nil {
		return nil, e
	} // Reserve all possible public bytes before either role can spend them.
	cmd, e := childCommand(WriterArgument)
	if e != nil {
		return nil, e
	}
	identity, e := buildIdentity()
	if e != nil {
		return nil, e
	}
	raw, feed, e := privatePipe()
	if e != nil {
		return nil, e
	}
	nonce, release, e := configureLaunch(cmd, "intel-progress", out, raw)
	if e != nil {
		raw.Close()
		feed.Close()
		return nil, e
	}
	sum := sha256.Sum256(data)
	cfg := progressConfig{nonce, len(data), hex.EncodeToString(sum[:])}
	work, cancel := context.WithCancel(ctx)
	aux := &runState{budget: s.budget, deadline: s.deadline, caller: s.caller, scan: s.scan, preparation: true, broken: s.broken}
	p := &intelProgress{stop: make(chan struct{}), done: make(chan error, 1), cancel: cancel}
	ready := make(chan error, 1)
	go func() {
		defer raw.Close()
		defer feed.Close()
		announced := false
		failure := aux.runChild(work, cmd, release, func(childCtx context.Context, c *channel, input io.Closer) error {
			joined := make(chan struct{})
			stop := context.AfterFunc(childCtx, func() { defer close(joined); feed.Close() })
			defer func() {
				if !stop() {
					<-joined
				}
			}()
			var h hello
			if c.expect("hello", &h) != nil || h.Build != identity || c.send("hello", hello{identity}) != nil || c.send("config", cfg) != nil {
				return errProtocol
			}
			if n, e := feed.Write(data); e != nil || n != len(data) {
				return errOutput
			}
			if feed.Close() != nil {
				return errOutput
			}
			var ack intelClosure
			if c.expect("ready", &ack) != nil || ack.Results != 0 {
				return errProtocol
			}
			ready <- nil
			announced = true
			select {
			case <-p.stop:
			case <-childCtx.Done():
				return errOutput
			}
			if c.send("stop", intelClosure{0}) != nil || input.Close() != nil {
				return errProtocol
			}
			var done progressDone
			if c.expect("written", &done) != nil || done.Size != cfg.Size || done.SHA256 != cfg.SHA256 || done.Rendered < 0 || done.Rendered > maxProgressBytes {
				return errOutput
			}
			if _, e := c.receive(); e != io.EOF {
				return errProtocol
			}
			return nil
		})
		if failure != nil {
			failed()
		}
		if !announced {
			ready <- failure
		}
		p.done <- failure
	}()
	if e := <-ready; e != nil {
		cancel()
		<-p.done
		return nil, e
	}
	return p, nil
}
func (p *intelProgress) finish() error {
	close(p.stop)
	e := <-p.done
	p.cancel()
	return e
}

func progressWriterMain(in io.Reader, out io.Writer) int {
	nonce, ids, e := launchCapability("intel-progress")
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
	c := newChannel(in, out, &traffic{})
	if c.send("hello", hello{identity}) != nil {
		return 2
	}
	var h hello
	var cfg progressConfig
	if c.expect("hello", &h) != nil || h.Build != identity || c.expect("config", &cfg) != nil || cfg.Nonce != nonce || cfg.Size < 1 || cfg.Size > 1024 {
		return 2
	}
	raw := os.NewFile(ids[1], "approved-progress-frames")
	public := os.NewFile(ids[0], "original-progress-output")
	if raw == nil || public == nil {
		return 2
	}
	defer raw.Close()
	defer public.Close()
	data, e := io.ReadAll(io.LimitReader(raw, int64(cfg.Size)+1))
	sum := sha256.Sum256(data)
	if e != nil || len(data) != cfg.Size || hex.EncodeToString(sum[:]) != cfg.SHA256 {
		return 2
	}
	frames := bytes.Split(data, []byte{'\n'})
	if len(frames) != 5 {
		return 2
	}
	for _, frame := range frames {
		if len(frame) < 1 || len(frame) > 128 {
			return 2
		}
	}
	if c.send("ready", intelClosure{0}) != nil {
		return 2
	}
	stopped := make(chan error, 1)
	go func() {
		var v intelClosure
		e := c.expect("stop", &v)
		if e == nil && v.Results != 0 {
			e = errProtocol
		}
		if e == nil {
			if _, end := c.receive(); end != io.EOF {
				e = errProtocol
			}
		}
		stopped <- e
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()
	rendered, index := 0, 0
	write := func(frame []byte) bool {
		if len(frame) > maxProgressBytes-rendered {
			return false
		}
		n, e := public.Write(frame)
		rendered += n
		return e == nil && n == len(frame)
	}
	for {
		select {
		case e := <-stopped:
			if e != nil {
				return 2
			}
			if rendered > 0 && !write(frames[4]) {
				return 2
			}
			if c.send("written", progressDone{cfg.Size, cfg.SHA256, rendered}) != nil {
				return 2
			}
			return 0
		case <-deadline.C:
			return 2
		case <-ticker.C:
			if !write(frames[index%4]) {
				return 2
			}
			index++
		}
	}
}
