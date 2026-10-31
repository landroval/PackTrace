package execution

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	"packtrace/internal/demo"
	"packtrace/internal/inspect"
	"packtrace/internal/jsoninput"
)

const (
	maxMessage = 1 << 20 // Encoded bytes, including the mandatory LF.
	maxTraffic = 64 << 20
	maxStderr  = 64 << 10
	maxInput   = 1 << 20
)

var errProtocol = errors.New("inspect-batch: worker-protocol")
var errLimit = errors.New("inspect-batch: worker-limit-exceeded")

type traffic struct {
	mu     sync.Mutex
	n      int
	stderr int
}

func (b *traffic) addStderr(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > maxStderr-b.stderr {
		return errLimit
	}
	b.stderr += n
	return nil
}

func (b *traffic) add(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > maxTraffic-b.n {
		return errLimit
	}
	b.n += n
	return nil
}

type channel struct {
	r              *bufio.Reader
	w              io.Writer
	budget         *traffic
	received, sent int
}

func newChannel(r io.Reader, w io.Writer, b *traffic) *channel {
	return &channel{r: bufio.NewReaderSize(r, 4096), w: w, budget: b}
}

type envelope struct {
	Version int             `json:"version"`
	Seq     int             `json:"seq"`
	Job     int             `json:"job"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}
type hello struct {
	Build string `json:"build"`
}
type config struct {
	Nonce   string `json:"nonce"`
	Profile string `json:"profile"`
}
type writerConfig struct {
	Nonce  string `json:"nonce"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type writerDone struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}
type start struct {
	Locked     int `json:"locked"`
	Advisories int `json:"advisories"`
}
type advisory struct {
	Index  int             `json:"index"`
	State  string          `json:"state"`
	Report *inspect.Result `json:"report"`
}
type candidate struct {
	Index int            `json:"index"`
	Value demo.Candidate `json:"value"`
}
type closure struct {
	Index       int `json:"index"`
	Candidates  int `json:"candidates"`
	Evaluations int `json:"evaluations"`
}
type diagnostic struct {
	Code string `json:"code"`
}
type done struct {
	Advisories int `json:"advisories"`
	Candidates int `json:"candidates"`
}

func decode(data []byte, v any) error {
	if _, code := jsoninput.Object(data, maxMessage); code != "" {
		return errProtocol
	}
	if !typedShape(data, reflect.TypeOf(v).Elem()) {
		return errProtocol
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errProtocol
	}
	return nil
}

// encoding/json accepts case-folded names, missing fields and null scalars.
// The private protocol does not: require the exact typed shape recursively.
func typedShape(data []byte, t reflect.Type) bool {
	if t == reflect.TypeOf(json.RawMessage{}) {
		return len(data) > 0 && data[0] == '{'
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(data, []byte("null")) {
			return true
		}
		return typedShape(data, t.Elem())
	}
	if bytes.Equal(data, []byte("null")) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil || fields == nil {
			return false
		}
		known := 0
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			raw, present := fields[name]
			if !present {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return false
			}
			known++
			if !typedShape(raw, f.Type) {
				return false
			}
		}
		return known == len(fields)
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil || values == nil {
			return false
		}
		for _, raw := range values {
			if !typedShape(raw, t.Elem()) {
				return false
			}
		}
	}
	return true
}

func (c *channel) send(kind string, v any) error {
	data, e := json.Marshal(v)
	if e != nil {
		return errProtocol
	}
	line, e := json.Marshal(envelope{1, c.sent + 1, 1, kind, data})
	if e != nil {
		return errProtocol
	}
	line = append(line, '\n')
	if len(line) > maxMessage {
		return errLimit
	}
	if e = c.budget.add(len(line)); e != nil {
		return e
	}
	n, e := c.w.Write(line)
	if e != nil || n != len(line) {
		return errProtocol
	}
	c.sent++
	return nil
}
func (c *channel) receive() (envelope, error) {
	var line []byte
	for {
		part, e := c.r.ReadSlice('\n')
		if c.budget.add(len(part)) != nil {
			return envelope{}, errLimit
		}
		if len(part) > maxMessage-len(line) {
			return envelope{}, errLimit
		}
		line = append(line, part...)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			if e == io.EOF && len(line) == 0 {
				return envelope{}, io.EOF
			}
			return envelope{}, errProtocol
		}
		break
	}
	var m envelope
	if decode(line, &m) != nil || m.Version != 1 || m.Job != 1 || m.Seq != c.received+1 || m.Type == "" || m.Data == nil {
		return envelope{}, errProtocol
	}
	c.received++
	return m, nil
}
func (c *channel) expect(kind string, v any) error {
	m, e := c.receive()
	if e != nil {
		return e
	}
	if m.Type != kind {
		return errProtocol
	}
	return decode(m.Data, v)
}
func buildIdentity() (string, error) {
	name, e := os.Executable()
	if e != nil {
		return "", errProtocol
	}
	f, e := os.Open(name)
	if e != nil {
		return "", errProtocol
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", errProtocol
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validProfile(s string) bool { return s == "explicit-only" || s == "npm-lock-v2-v3" }
func inputCode(s string) bool {
	switch s {
	case "inspect-batch: invalid-profile", "inspect-batch: read-failed", "inspect-batch: limit-exceeded", "inspect-batch: invalid-input", "inspect-batch: invalid-lockfile":
		return true
	}
	return false
}
