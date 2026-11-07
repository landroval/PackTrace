package intelstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type failedHTTPOutput struct{}

func (failedHTTPOutput) Write([]byte) (int, error) { return 0, errors.New("owned output failure") }
func TestHTTPBodyQuotaAndFailedOutputRemainCharged(t *testing.T) {
	b := &Budget{HTTPBytes: (2 << 30) - 1}
	input := strings.NewReader("ab")
	var out bytes.Buffer
	if used, e := readHTTPBody(context.Background(), b, input, 4, &out); !errors.Is(e, ErrLimit) || used != 1 || b.HTTPBytes != 2<<30 || input.Len() != 1 {
		t.Fatal("network quota over-read or refunded", used, e, b, input.Len())
	}
	b = &Budget{}
	if _, e := readHTTPBody(context.Background(), b, strings.NewReader("actual"), 100, failedHTTPOutput{}); e == nil || b.HTTPBytes != 6 {
		t.Fatal("failed output refunded received body", e, b)
	}
	b = &Budget{}
	if _, e := readHTTPBody(context.Background(), b, strings.NewReader("oversized"), 3, io.Discard); !errors.Is(e, ErrLimit) || b.HTTPBytes != 4 {
		t.Fatal("response sentinel not charged", e, b)
	}
}
func ownedMappedClient(t *testing.T, handler http.Handler) (*http.Client, func()) {
	t.Helper()
	server := ownedSourceTLSServer(t, handler)
	client := newPublicHTTP()
	tr := client.Transport.(*http.Transport)
	tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialPublic(ctx, address, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}, func(ctx context.Context, network, literal string) (net.Conn, error) {
			if literal != "8.8.8.8:443" {
				return nil, ErrUntrusted
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		})
	}
	return client, func() { tr.CloseIdleConnections(); server.Close() }
}
func TestHTTPDeadlineIsNotRenewedAcrossAttempts(t *testing.T) {
	client, close := ownedMappedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		io.WriteString(w, "late")
	}))
	defer close()
	b := &Budget{Deadline: time.Now().Add(10 * time.Millisecond)}
	if _, e := fetchUsing(context.Background(), b, requestSpec{kind: requestArchiveMeta}, io.Discard, client); !errors.Is(e, context.DeadlineExceeded) || b.Requests != 1 {
		t.Fatal("deadline renewed/ignored", e, b)
	}
}
func TestHTTPConditionalAndGenerationEvidenceCannotContradictRequest(t *testing.T) {
	for _, mode := range []string{"etag", "generation"} {
		t.Run(mode, func(t *testing.T) {
			client, close := ownedMappedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "etag" {
					w.Header().Set("ETag", "\"other\"")
					w.WriteHeader(304)
				} else {
					w.Header().Set("X-Goog-Generation", "456")
					io.WriteString(w, "body")
				}
			}))
			defer close()
			spec := requestSpec{kind: requestArchive, generation: "123"}
			if mode == "etag" {
				spec.etag = "\"expected\""
			}
			if _, e := fetchUsing(context.Background(), &Budget{}, spec, io.Discard, client); e == nil {
				t.Fatal("contradictory response minted evidence")
			}
		})
	}
}
