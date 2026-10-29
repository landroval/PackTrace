package integrity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// Literal vectors independently generated with Python hashlib (independent-vectors.json).
func TestSetVectors(t *testing.T) {
	cases := []struct{ text, token, digest, algorithm string }{
		{"", empty256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		{"", "sha384-OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "sha384"},
		{"", "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "sha512"},
		{"abc", abc256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256"},
		{"abc", "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "sha384"},
		{"abc", "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "sha512"},
		{"abd", "sha256-pS0VnyYrLG3bckphhAvvw26zDIiHekAwtly+himESck=", "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9", "sha256"},
		{"abd", "sha384-XRW867ll+neSbCNHHJbjoyazY/XxBcPvF8/QM7lzT6RlVvgaJrswRNLdpQSBMl73", "5d15bcebb965fa77926c23471c96e3a326b363f5f105c3ef17cfd033b9734fa46556f81a26bb3044d2dda50481325ef7", "sha384"},
		{"abd", "sha512-GphAwnpc8i2rBgzdioPaKw+8sa61LU+dOJS2OQg+IFpas/avrushuOmbXg/pPar6q+7ydNpdbq3MnbNuW29kxA==", "1a9840c27a5cf22dab060cdd8a83da2b0fbcb1aeb52d4f9d3894b639083e205a5ab3f6afaeeb21b8e99b5e0fe93daafaabeef274da5d6eadcc9db36e5b6f64c4", "sha512"},
	}
	for _, tc := range cases {
		t.Run(tc.algorithm+"/"+tc.text, func(t *testing.T) {
			got, err := CheckReferenceDigestSet(context.Background(), tc.token, strings.NewReader(tc.text), int64(len(tc.text)))
			want, _ := hex.DecodeString(tc.digest)
			if err != nil || got.State != DigestMatch || got.Algorithm != tc.algorithm || got.BytesRead != int64(len(tc.text)) || !bytes.Equal(got.ObservedDigest, want) || len(got.ExpectedDigests) != 1 || !bytes.Equal(got.ExpectedDigests[0], want) {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
}

func TestSetStrengthAndAlternatives(t *testing.T) {
	abc512 := "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
	abd512 := "sha512-GphAwnpc8i2rBgzdioPaKw+8sa61LU+dOJS2OQg+IFpas/avrushuOmbXg/pPar6q+7ydNpdbq3MnbNuW29kxA=="
	abc384 := "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn"
	abd384 := "sha384-XRW867ll+neSbCNHHJbjoyazY/XxBcPvF8/QM7lzT6RlVvgaJrswRNLdpQSBMl73"
	for _, tc := range []struct {
		name, claim, algorithm string
		match                  bool
		alternatives           []string
	}{
		{"downgrade", abc256 + " " + abd512, "sha512", false, []string{abd512}},
		{"strongest match weaker mismatch", abd384 + " " + abc512, "sha512", true, []string{abc512}},
		{"384 downgrade", abc256 + " " + abd384, "sha384", false, []string{abd384}},
		{"same algorithm second wins", abd512 + " " + abc256 + " " + abc512, "sha512", true, []string{abd512, abc512}},
		{"same algorithm all miss", abd512 + "\t" + abd512, "sha512", false, []string{abd512, abd512}},
		{"source order and 384 selection", abd384 + " " + abc256 + " " + abc384, "sha384", true, []string{abd384, abc384}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{r: strings.NewReader("abc")}
			got, err := CheckReferenceDigestSet(context.Background(), tc.claim, r, 3)
			wantState := DigestMismatch
			if tc.match {
				wantState = DigestMatch
			}
			if err != nil || got.State != wantState || got.Algorithm != tc.algorithm || got.BytesRead != 3 || len(got.ExpectedDigests) != len(tc.alternatives) || r.bytes != 3 || r.reads != 2 || r.maxRequest > 32*1024 {
				t.Fatalf("got %+v %v reader %+v", got, err, r)
			}
			for i, token := range tc.alternatives {
				want, e := base64.StdEncoding.DecodeString(token[7:])
				if e != nil || !bytes.Equal(got.ExpectedDigests[i], want) {
					t.Fatalf("alternative %d: %+v", i, got)
				}
			}
			original := got.ObservedDigest[0]
			got.ExpectedDigests[0][0] ^= 255
			if got.ObservedDigest[0] != original || (len(got.ExpectedDigests) > 1 && got.ExpectedDigests[0][0] == got.ExpectedDigests[1][0] && tc.alternatives[0] == tc.alternatives[1]) {
				t.Fatal("digest alias")
			}
		})
	}
}

func TestSetAdmission(t *testing.T) {
	bad := []string{"", " \t\n\r\f ", "sha1-ignored " + abc256, abc256 + " unknown", abc256 + " md5-x", abc256 + " sha256-", "SHA256-" + abc256[7:] + " " + abc256, abc256 + " " + strings.TrimSuffix(abc256, "="), abc256 + " " + abc256[:len(abc256)-2] + "1=", abc256 + " " + strings.ReplaceAll(abc256, "+", "-"), abc256 + "?x", abc256 + "\v" + abc256, strings.Repeat(abc256+" ", 17), strings.Repeat(" ", 2049), abc256 + strings.Repeat(" ", 2049-len(abc256))}
	for i, claim := range bad {
		r := &countingReader{r: strings.NewReader("abc")}
		got, err := CheckReferenceDigestSet(context.Background(), claim, r, 3)
		if err != nil || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) || r.reads != 0 {
			t.Fatalf("bad %d: %+v %v reads %d", i, got, err, r.reads)
		}
	}
	valid16 := strings.Join([]string{abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256, abc256}, " ")
	got, err := CheckReferenceDigestSet(context.Background(), valid16, strings.NewReader("abc"), 3)
	if err != nil || got.State != DigestMatch || len(got.ExpectedDigests) != 16 {
		t.Fatalf("16: %+v %v", got, err)
	}
	exact := abc256 + strings.Repeat(" ", 2048-len(abc256))
	got, err = CheckReferenceDigestSet(context.Background(), exact, strings.NewReader("abc"), 3)
	if err != nil || got.State != DigestMatch {
		t.Fatalf("2048: %+v %v", got, err)
	}
	spaced := " \t\n\r\f" + abc256 + "\f\r\n\t  "
	got, err = CheckReferenceDigestSet(context.Background(), spaced, strings.NewReader("abc"), 3)
	if err != nil || got.State != DigestMatch {
		t.Fatalf("delimiters: %+v %v", got, err)
	}
}

func TestSetStreamSafety(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		budget     int64
		state      DigestState
		fail       bool
		consumed   int
	}{
		{"exact", "abc", 3, DigestMatch, false, 3}, {"mismatch", "abd", 3, DigestMismatch, false, 3}, {"empty", "", 0, DigestMismatch, false, 0}, {"zero over", "a", 0, 0, true, 1}, {"cap plus one", "abcMORE", 3, 0, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{r: strings.NewReader(tc.data)}
			got, err := CheckReferenceDigestSet(context.Background(), abc256, r, tc.budget)
			if (err != nil) != tc.fail || (!tc.fail && got.State != tc.state) || (tc.fail && !reflect.DeepEqual(got, ReferenceDigestSetCheck{})) || r.bytes != tc.consumed || r.maxRequest > 32*1024 {
				t.Fatalf("%+v %v %+v", got, err, r)
			}
		})
	}
	for _, budget := range []int64{-1, 512*1024*1024 + 1} {
		r := &countingReader{r: strings.NewReader("abc")}
		got, err := CheckReferenceDigestSet(context.Background(), abc256, r, budget)
		if err == nil || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) || r.reads != 0 {
			t.Fatalf("budget %+v %v %+v", got, err, r)
		}
	}
	for _, tc := range []struct {
		ctx context.Context
		in  io.Reader
	}{{nil, strings.NewReader("abc")}, {context.Background(), nil}} {
		got, err := CheckReferenceDigestSet(tc.ctx, abc256, tc.in, 3)
		if err == nil || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) {
			t.Fatalf("arg %+v %v", got, err)
		}
	}
	r := &countingReader{r: strings.NewReader("abc")}
	got, err := CheckReferenceDigestSet(context.Background(), abc256, r, 512*1024*1024)
	if err != nil || got.State != DigestMatch || r.maxRequest > 32*1024 {
		t.Fatalf("max %+v %v %+v", got, err, r)
	}
}

func TestSetBoundedStream(t *testing.T) {
	r := &countingReader{r: strings.NewReader(strings.Repeat("x", 32*1024+1))}
	got, err := CheckReferenceDigestSet(context.Background(), abc256+" "+abc256, r, 32*1024)
	if err == nil || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) || r.bytes != 32*1024+1 || r.maxRequest != 32*1024 {
		t.Fatalf("bounded stream: %+v %v %+v", got, err, r)
	}
}

func TestSetReadAndCancellation(t *testing.T) {
	secret := errors.New("source secret")
	for _, tc := range []struct {
		name  string
		steps []func([]byte) (int, error)
		want  DigestState
		fail  bool
	}{
		{"short then EOF", []func([]byte) (int, error){put("a", nil), put("b", nil), put("c", io.EOF)}, DigestMatch, false},
		{"read error", []func([]byte) (int, error){put("abc", secret)}, 0, true},
		{"nonprogress", func() []func([]byte) (int, error) {
			a := make([]func([]byte) (int, error), 101)
			for i := range a {
				a[i] = put("", nil)
			}
			return a
		}(), 0, true},
		{"bad count", []func([]byte) (int, error){func(p []byte) (int, error) { return len(p) + 1, nil }}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &scriptedReader{steps: tc.steps}
			got, err := CheckReferenceDigestSet(context.Background(), abc256, r, 3)
			if (err != nil) != tc.fail || (!tc.fail && got.State != tc.want) || (tc.fail && (!reflect.DeepEqual(got, ReferenceDigestSetCheck{}) || errors.Is(err, secret) || strings.Contains(err.Error(), "secret"))) || r.calls > 101 {
				t.Fatalf("%+v %v calls %d", got, err, r.calls)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &countingReader{r: strings.NewReader("abc")}
	got, err := CheckReferenceDigestSet(ctx, abc256, r, 3)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) || r.reads != 0 {
		t.Fatalf("pre %+v %v %+v", got, err, r)
	}
	ctx, cancel = context.WithCancel(context.Background())
	got, err = CheckReferenceDigestSet(ctx, abc256, &scriptedReader{steps: []func([]byte) (int, error){func(p []byte) (int, error) { copy(p, "abc"); cancel(); return 3, io.EOF }}}, 3)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, ReferenceDigestSetCheck{}) {
		t.Fatalf("post %+v %v", got, err)
	}
}
