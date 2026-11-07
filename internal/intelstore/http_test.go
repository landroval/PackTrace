package intelstore

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestMappedAndReservedAddressesAreNotPublic(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "10.1.1.1", "192.0.2.1", "198.18.1.1", "240.0.0.1", "2001:db8::1", "64:ff9b::7f00:1", "3fff::1"} {
		if publicAddress(netip.MustParseAddr(raw)) {
			t.Fatal("reserved destination admitted", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "::ffff:8.8.8.8", "2607:f8b0:4000::1"} {
		if !publicAddress(netip.MustParseAddr(raw)) {
			t.Fatal("public positive refused", raw)
		}
	}
}
func TestDialUsesOnlyAlreadyValidatedLiteral(t *testing.T) {
	resolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	seen := ""
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		seen = address
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	c, e := dialPublic(context.Background(), "storage.googleapis.com:443", resolver, dial)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if seen != "8.8.8.8:443" {
		t.Fatal("DNS name rebound at dial", seen)
	}
	seen = ""
	resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, e := dialPublic(context.Background(), "storage.googleapis.com:443", resolver, dial); e == nil || seen != "" {
		t.Fatal("mixed private DNS admitted")
	}
}

// An owned TLS fixture uses a test-only dial mapping and a fixture CA with
// real admitted-host SANs; production has no resolver/dial/CA bypass switch.
func TestHTTPCountsRetryBodiesAndIgnoresProxyEnvironment(t *testing.T) {
	calls := 0
	server := ownedSourceTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("ambient credential forwarded")
		}
		if r.Host != "storage.googleapis.com" {
			t.Error("wrong authority")
		}
		if calls < 3 {
			w.WriteHeader(503)
			io.WriteString(w, "bad")
			return
		}
		io.WriteString(w, "good")
	}))
	defer server.Close()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := newPublicHTTP()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	b := &Budget{}
	var output bytes.Buffer
	evidence, e := fetchUsing(context.Background(), b, requestSpec{kind: requestArchiveMeta}, &output, client)
	if e != nil || calls != 3 || b.Requests != 3 || b.HTTPBytes != 10 || evidence.status != 200 || output.String() != "good" {
		t.Fatal("retry accounting/contamination", e, calls, b, output.String())
	}
}
func TestRedirectPrivateAuthorityFailsAfterChargingBody(t *testing.T) {
	calls := 0
	server := ownedSourceTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://127.0.0.1/secret")
		w.WriteHeader(302)
		io.WriteString(w, "redirect-body")
	}))
	defer server.Close()
	client := newPublicHTTP()
	tr := client.Transport.(*http.Transport)
	tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer tr.CloseIdleConnections()
	b := &Budget{}
	if _, e := fetchUsing(context.Background(), b, requestSpec{kind: requestArchiveMeta}, io.Discard, client); e == nil || calls != 1 || b.HTTPBytes != uint64(len("redirect-body")) {
		t.Fatal("unsafe redirect or uncharged rejected body", e, calls, b)
	}
}
func TestPublicRequestDoesNotAcceptURLOrEscapedID(t *testing.T) {
	for _, id := range []string{"https://localhost/", "OWNED%2fsecret", "OWNED/secret", "user@host", "x?auth=secret", strings.Repeat("a", 241)} {
		if _, e := (requestSpec{kind: requestRecord, id: id}).url(); e == nil {
			t.Fatal("arbitrary endpoint admitted", id)
		}
	}
}
