package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func wire(seq int, kind string, data any) string {
	raw, _ := json.Marshal(data)
	line, _ := json.Marshal(envelope{1, seq, 1, kind, raw})
	return string(line) + "\n"
}
func TestStrictMessageBoundary(t *testing.T) {
	valid := wire(1, "start", start{1, 1})
	for _, tc := range []struct{ name, wire string }{
		{"duplicate", strings.Replace(valid, `"job":1`, `"job":1,"job":1`, 1)},
		{"unknown", strings.Replace(valid, `"job":1`, `"job":1,"PRIVATE":1`, 1)},
		{"casefold", strings.Replace(valid, `"job":1`, `"JOB":1`, 1)},
		{"missing", strings.Replace(valid, `"job":1,`, "", 1)},
		{"null", strings.Replace(valid, `"job":1`, `"job":null`, 1)},
		{"type", strings.Replace(valid, `"job":1`, `"job":"1"`, 1)},
		{"version", strings.Replace(valid, `"version":1`, `"version":2`, 1)},
		{"sequence", strings.Replace(valid, `"seq":1`, `"seq":2`, 1)},
		{"job", strings.Replace(valid, `"job":1`, `"job":2`, 1)},
		{"truncated", strings.TrimSuffix(valid, "\n")},
		{"oversize", strings.Repeat(" ", maxMessage) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newChannel(strings.NewReader(tc.wire), io.Discard, &traffic{})
			_, e := c.receive()
			if e == nil {
				t.Fatal("accepted invalid envelope")
			}
			if tc.name == "oversize" && !errors.Is(e, errLimit) {
				t.Fatal("encoded cap not enforced before decode", e)
			}
		})
	}
}
func TestStrictPayloadBoundary(t *testing.T) {
	for _, data := range []string{`{"locked":1,"advisories":1,"extra":1}`, `{"locked":1,"locked":1,"advisories":1}`, `{"LOCKED":1,"advisories":1}`, `{"locked":null,"advisories":1}`, `{"advisories":1}`, `{"locked":1,"advisories":"1"}`} {
		var s start
		if decode([]byte(data), &s) == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
func TestExactEncodedCapsAndCombinedBudget(t *testing.T) {
	base := wire(1, "hello", hello{""})
	line := wire(1, "hello", hello{strings.Repeat("x", maxMessage-len(base))})
	if len(line) != maxMessage {
		t.Fatal(len(line))
	}
	c := newChannel(strings.NewReader(line), io.Discard, &traffic{})
	if _, e := c.receive(); e != nil {
		t.Fatal("exact cap rejected", e)
	}
	c = newChannel(strings.NewReader(line+" "), io.Discard, &traffic{})
	c.budget.n = maxTraffic - len(line)
	if _, e := c.receive(); e != nil {
		t.Fatal(e)
	}
	if e := c.send("hello", hello{"x"}); !errors.Is(e, errLimit) {
		t.Fatal("both directions not counted", e)
	}
	var out bytes.Buffer
	c = newChannel(strings.NewReader(""), &out, &traffic{})
	if e := c.send("hello", hello{strings.Repeat("x", maxMessage-len(base))}); e != nil || out.Len() != maxMessage {
		t.Fatal("send exact cap", e, out.Len())
	}
	if e := c.send("hello", hello{strings.Repeat("x", maxMessage)}); !errors.Is(e, errLimit) {
		t.Fatal("send over cap", e)
	}
}
func TestReplayAndTypedDoneRules(t *testing.T) {
	for _, input := range []string{
		wire(1, "done", done{}),
		wire(1, "start", start{0, 1}) + wire(2, "done", done{}),
		wire(1, "diagnostic", diagnostic{"PRIVATE"}) + wire(2, "done", done{}),
		wire(1, "diagnostic", diagnostic{"inspect-batch: invalid-input"}) + wire(2, "done", done{}) + wire(3, "done", done{}),
		wire(1, "start", start{0, 1}) + wire(1, "start", start{0, 1}),
	} {
		if _, e := receiveResults(newChannel(strings.NewReader(input), io.Discard, &traffic{}), "explicit-only"); e == nil {
			t.Fatalf("false completion accepted %s", input)
		}
	}
}
func TestFragmentedReads(t *testing.T) {
	c := newChannel(&oneByte{strings.NewReader(wire(1, "start", start{1, 1}))}, io.Discard, &traffic{})
	var s start
	if e := c.expect("start", &s); e != nil || s.Locked != 1 || s.Advisories != 1 {
		t.Fatal(s, e)
	}
}

type oneByte struct{ io.Reader }

func (r *oneByte) Read(p []byte) (int, error) { return r.Reader.Read(p[:1]) }
func Example_wireLimits() {
	fmt.Println(maxMessage, maxTraffic, maxStderr) // Output: 1048576 67108864 65536
}
