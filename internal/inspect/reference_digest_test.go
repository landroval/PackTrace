package inspect

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const abc256 = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
const abc384 = "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn"
const abc512 = "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="

type unreadableDigest struct{}

func (unreadableDigest) Read([]byte) (int, error) { panic("unexpected read") }

type privateDigestError struct{}

func (privateDigestError) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-READER-ERROR") }

type chunkDigest struct{ data []byte }

func (r *chunkDigest) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data[:1])
	r.data = r.data[n:]
	return n, nil
}

func TestReferenceDigestStates(t *testing.T) {
	for _, tc := range []struct{ sri, algorithm string }{{abc256, "sha256"}, {abc384, "sha384"}, {abc512, "sha512"}} {
		for _, input := range []struct{ text, state string }{{"abc", "match"}, {"abd", "mismatch"}} {
			r, e := ReadReferenceDigest(context.Background(), tc.sri, strings.NewReader(input.text), 3)
			if e != nil || r.State != input.state || r.Algorithm != tc.algorithm || r.BytesRead != 3 || r.ExitCode != 3 {
				t.Fatalf("%s %s: %+v %v", tc.algorithm, input.state, r, e)
			}
			for _, format := range []string{"terminal", "json"} {
				b, e := RenderReferenceDigest(r, format)
				if e != nil || !strings.Contains(string(b), input.state) || !strings.Contains(string(b), tc.algorithm) || !strings.Contains(string(b), "3") || !strings.Contains(string(b), "archive") {
					t.Fatalf("%s: %q %v", format, b, e)
				}
				for _, secret := range []string{tc.sri, "ungWv48B", "PRIVATE", "ba7816bf"} {
					if strings.Contains(string(b), secret) {
						t.Fatal("digest leaked", secret)
					}
				}
			}
		}
	}
}
func TestReferenceDigestUnknownWithoutRead(t *testing.T) {
	for _, sri := range []string{"", "sha1-PRIVATE", abc256 + " " + abc384, "sha256-PRIVATE"} {
		r, e := ReadReferenceDigest(context.Background(), sri, unreadableDigest{}, 0)
		if e != nil || r.State != "unknown" || r.Algorithm != "unknown" || r.BytesRead != 0 || r.ExitCode != 3 {
			t.Fatal(r, e)
		}
		b, e := RenderReferenceDigest(r, "json")
		if e != nil || !strings.Contains(string(b), `"scope": "supplied-reference-bytes"`) || !strings.Contains(string(b), `"schema": "packtrace.reference-digest.v1"`) || !strings.Contains(string(b), `"privacy": "portable"`) || !strings.Contains(string(b), `"experimental": true`) || !strings.Contains(string(b), `"exit_code": 3`) || strings.Contains(string(b), sri) && sri != "" {
			t.Fatal(string(b), e)
		}
	}
}
func TestReferenceDigestBoundsAndErrors(t *testing.T) {
	empty := "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	for _, tc := range []struct {
		sri   string
		in    io.Reader
		max   int64
		state string
		fatal bool
	}{
		{empty, strings.NewReader(""), 0, "match", false}, {abc256, &chunkDigest{[]byte("abc")}, 3, "match", false},
		{abc256, strings.NewReader("a\x00c"), 3, "mismatch", false}, {abc256, strings.NewReader("a"), 0, "", true},
		{abc256, strings.NewReader("abc"), 2, "", true}, {abc256, privateDigestError{}, 3, "", true},
		{abc256, unreadableDigest{}, -1, "", true}, {abc256, unreadableDigest{}, 512*1024*1024 + 1, "", true},
	} {
		r, e := ReadReferenceDigest(context.Background(), tc.sri, tc.in, tc.max)
		if (e != nil) != tc.fatal || (!tc.fatal && r.State != tc.state) || (tc.fatal && (strings.Contains(e.Error(), "PRIVATE") || r.State != "")) {
			t.Fatal(r, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e := ReadReferenceDigest(ctx, abc256, unreadableDigest{}, 3)
	if e == nil || r.State != "" || strings.Contains(e.Error(), "context") {
		t.Fatal(r, e)
	}
	if _, e = RenderReferenceDigest(ReferenceDigestResult{}, "invalid"); e == nil {
		t.Fatal("invalid format accepted")
	}
}
