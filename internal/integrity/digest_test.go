package integrity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

const abc256 = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
const empty256 = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

// These are literal, independently generated hashlib vectors, not calculated by the code under test.
func TestKnownVectors(t *testing.T) {
	cases := []struct{ name, input, sri, digest, algorithm string }{
		{"empty256", "", empty256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		{"empty384", "", "sha384-OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "sha384"},
		{"empty512", "", "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "sha512"},
		{"abc256", "abc", abc256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256"},
		{"abc384", "abc", "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "sha384"},
		{"abc512", "abc", "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "sha512"},
		{"binary256", "owned synthetic reference\x00\xff", "sha256-OWYjP0lznEr5gEG5XWp8Qr3UnjJeSEIDBn5sSU7EbYU=", "3966233f49739c4af98041b95d6a7c42bdd49e325e484203067e6c494ec46d85", "sha256"},
		{"binary384", "owned synthetic reference\x00\xff", "sha384-oagu/NoYTQHs6dTvO3MUIr2+wOI/mq0yftNpV2D2ZWgNo/IA2T6E/HekPvBMtYXq", "a1a82efcda184d01ece9d4ef3b731422bdbec0e23f9aad327ed3695760f665680da3f200d93e84fc77a43ef04cb585ea", "sha384"},
		{"binary512", "owned synthetic reference\x00\xff", "sha512-W9rs3EIQvCRA84OtXMgpt9JjcP6ezQUGJcP3iwDVitCWTkgnt7t+37HhhyVMNB9p7ZgyhMjysUfFTpzSXzxj/w==", "5bdaecdc4210bc2440f383ad5cc829b7d26370fe9ecd050625c3f78b00d58ad0964e4827b7bb7edfb1e187254c341f69ed983284c8f2b147c54e9cd25f3c63ff", "sha512"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckReferenceDigest(context.Background(), tc.sri, strings.NewReader(tc.input), int64(len(tc.input)))
			want, _ := hex.DecodeString(tc.digest)
			if err != nil || got.State != DigestMatch || got.Algorithm != tc.algorithm || got.BytesRead != int64(len(tc.input)) || !bytes.Equal(got.ExpectedDigest, want) || !bytes.Equal(got.ObservedDigest, want) {
				t.Fatalf("got %+v, %v; want match %x", got, err, want)
			}
			got.ExpectedDigest[0] ^= 0xff
			if got.ObservedDigest[0] != want[0] {
				t.Fatal("digest slices alias")
			}
		})
	}
}

type countingReader struct {
	reads      int
	bytes      int
	maxRequest int
	r          io.Reader
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	if len(p) > c.maxRequest {
		c.maxRequest = len(p)
	}
	n, e := c.r.Read(p)
	c.bytes += n
	return n, e
}
func TestAdmissionWithoutReads(t *testing.T) {
	claims := []string{"", "sha1-x", "md5-x", "SHA256-" + abc256[7:], "sha256-", " sha256-" + abc256[7:], abc256 + " ", abc256 + "\n", abc256[:12] + "\r\n" + abc256[12:], abc256 + " " + abc256, abc256 + "?x", strings.TrimSuffix(abc256, "="), abc256[:len(abc256)-2] + "1=", strings.ReplaceAll(abc256, "+", "-"), "sha256-" + strings.Repeat("A", 44), "sha256-" + strings.Repeat("A", 400000)}
	for _, claim := range claims {
		t.Run(claim[:min(len(claim), 20)], func(t *testing.T) {
			r := &countingReader{r: strings.NewReader("abc")}
			got, err := CheckReferenceDigest(context.Background(), claim, r, 3)
			if err != nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) || r.reads != 0 {
				t.Fatalf("unexpected admission: %+v %v reads %d", got, err, r.reads)
			}
		})
	}
}

func TestMismatchAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name, data  string
		budget      int64
		match, fail bool
		consumed    int
	}{
		{"corruption", "abd", 3, false, false, 3}, {"truncated", "ab", 3, false, false, 2},
		{"exact", "abc", 3, true, false, 3}, {"over", "abcd", 3, false, true, 4},
		{"zero-empty", "", 0, false, false, 0}, {"zero-over", "a", 0, false, true, 1},
		{"prefix-plus-extra", "abcMORE", 3, false, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{r: strings.NewReader(tc.data)}
			got, err := CheckReferenceDigest(context.Background(), abc256, r, tc.budget)
			if tc.fail {
				if err == nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) {
					t.Fatalf("limit: %+v %v", got, err)
				}
			} else if err != nil || (got.State == DigestMatch) != tc.match || (got.State != DigestMatch && got.State != DigestMismatch) {
				t.Fatalf("verdict: %+v %v", got, err)
			}
			if r.bytes != tc.consumed || r.maxRequest > 32*1024 || r.reads == 0 {
				t.Fatalf("reader: %+v", r)
			}
		})
	}
}

func TestBoundedStreaming(t *testing.T) {
	data := strings.Repeat("x", 32*1024+1)
	r := &countingReader{r: strings.NewReader(data)}
	got, err := CheckReferenceDigest(context.Background(), abc256, r, 32*1024)
	if err == nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) || r.bytes != 32*1024+1 || r.maxRequest != 32*1024 {
		t.Fatalf("bounded read: %+v %v %+v", got, err, r)
	}
}

func TestBadArgumentsAndConfig(t *testing.T) {
	for _, budget := range []int64{-1, 512*1024*1024 + 1} {
		r := &countingReader{r: strings.NewReader("abc")}
		got, err := CheckReferenceDigest(context.Background(), abc256, r, budget)
		if err == nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) || r.reads != 0 {
			t.Fatalf("budget: %+v %v %+v", got, err, r)
		}
	}
	for _, tc := range []struct {
		ctx context.Context
		r   io.Reader
	}{{nil, strings.NewReader("abc")}, {context.Background(), nil}} {
		got, err := CheckReferenceDigest(tc.ctx, abc256, tc.r, 3)
		if err == nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) {
			t.Fatalf("argument: %+v %v", got, err)
		}
	}
	r := &countingReader{r: strings.NewReader("abc")}
	got, err := CheckReferenceDigest(context.Background(), abc256, r, 512*1024*1024)
	if err != nil || got.State != DigestMatch || r.bytes != 3 || r.maxRequest > 32*1024 {
		t.Fatalf("cap accepted: %+v %v %+v", got, err, r)
	}
}

type scriptedReader struct {
	steps []func([]byte) (int, error)
	calls int
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	i := r.calls
	r.calls++
	if i >= len(r.steps) {
		return 0, io.EOF
	}
	return r.steps[i](p)
}
func put(s string, e error) func([]byte) (int, error) {
	return func(p []byte) (int, error) { return copy(p, s), e }
}
func TestReadSemantics(t *testing.T) {
	t.Run("short-and-data-EOF", func(t *testing.T) {
		r := &scriptedReader{steps: []func([]byte) (int, error){put("a", nil), put("b", nil), put("c", io.EOF)}}
		got, err := CheckReferenceDigest(context.Background(), abc256, r, 3)
		if err != nil || got.State != DigestMatch {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("data-error-private", func(t *testing.T) {
		secret := errors.New("source secret")
		r := &scriptedReader{steps: []func([]byte) (int, error){put("abc", secret)}}
		got, err := CheckReferenceDigest(context.Background(), abc256, r, 3)
		if err == nil || errors.Is(err, secret) || strings.Contains(err.Error(), "secret") || !reflect.DeepEqual(got, ReferenceDigestCheck{}) {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("nonprogress", func(t *testing.T) {
		r := &scriptedReader{steps: make([]func([]byte) (int, error), 10000)}
		for i := range r.steps {
			r.steps[i] = put("", nil)
		}
		got, err := CheckReferenceDigest(context.Background(), abc256, r, 3)
		if err == nil || !reflect.DeepEqual(got, ReferenceDigestCheck{}) || r.calls >= 10000 {
			t.Fatalf("%+v %v calls %d", got, err, r.calls)
		}
	})
}
func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &countingReader{r: strings.NewReader("abc")}
	got, err := CheckReferenceDigest(ctx, abc256, r, 3)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ReferenceDigestCheck{}) || r.reads != 0 {
		t.Fatalf("before: %+v %v %+v", got, err, r)
	}
	ctx, cancel = context.WithCancel(context.Background())
	r2 := &scriptedReader{steps: []func([]byte) (int, error){func(p []byte) (int, error) { copy(p, "abc"); cancel(); return 3, io.EOF }}}
	got, err = CheckReferenceDigest(ctx, abc256, r2, 3)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ReferenceDigestCheck{}) {
		t.Fatalf("after EOF: %+v %v", got, err)
	}
}
