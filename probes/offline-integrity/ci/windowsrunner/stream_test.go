package main

import (
	"strings"
	"testing"
)

func TestCaptureLimitRetainsExactPrefixAndStops(t *testing.T) {
	stopped := 0
	c := capture{cap: 4, complete: true, stop: func() { stopped++ }}
	n, e := c.Write([]byte("abcdef"))
	if n != 4 || e != errCapture || string(c.data) != "abcd" || c.complete || stopped != 1 {
		t.Fatal(n, e, string(c.data), c.complete, stopped)
	}
}
func TestCountsCannotPromotePartialOrFailedStream(t *testing.T) {
	for _, s := range []string{"", `{"Action":"pass","Test":"T"}`, "not-json\n"} {
		if _, e := testCounts([]byte(s)); e == nil {
			t.Fatal("incomplete admitted", s)
		}
	}
	c, e := testCounts([]byte(strings.Join([]string{`{"Action":"pass","Test":"T"}`, `{"Action":"fail","Package":"P"}`, `{"Action":"build-fail","Package":"Q"}`, ""}, "\n")))
	if e != nil || c.Passed != 1 || c.Failed != 1 || c.BuildFailed != 1 {
		t.Fatal(c, e)
	}
}
