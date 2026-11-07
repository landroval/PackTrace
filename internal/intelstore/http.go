package intelstore

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type requestKind uint8

const (
	requestArchiveMeta requestKind = iota
	requestChangesMeta
	requestArchive
	requestChanges
	requestRecord
)

type requestSpec struct {
	kind                 requestKind
	id, generation, etag string
}
type responseEvidence struct {
	status           int
	bytes            uint64
	etag, generation string
	conditional      bool
}

func (s requestSpec) url() (*url.URL, error) {
	var path string
	switch s.kind {
	case requestArchiveMeta:
		path = "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/npm%2Fall.zip"
	case requestChangesMeta:
		path = "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o/modified_id.csv"
	case requestArchive:
		path = "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"
	case requestChanges:
		path = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
	case requestRecord:
		if !publicRecordID(s.id) {
			return nil, ErrUntrusted
		}
		path = "https://api.osv.dev/v1/vulns/" + s.id
	default:
		return nil, ErrUntrusted
	}
	u, e := url.Parse(path)
	if e != nil {
		return nil, ErrUntrusted
	}
	if s.generation != "" {
		n, e := strconv.ParseUint(s.generation, 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != s.generation || s.kind != requestArchive && s.kind != requestChanges {
			return nil, ErrUntrusted
		}
		q := u.Query()
		q.Set("generation", s.generation)
		u.RawQuery = q.Encode()
	}
	if len(s.etag) > 512 || strings.ContainsAny(s.etag, "\r\n\x00") {
		return nil, ErrUntrusted
	}
	return u, nil
}

var reservedPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, p := range reservedPublicPrefixes {
		if p.Contains(address) {
			return false
		}
	}
	return true
}
func sourceHost(host string) bool { return host == "storage.googleapis.com" || host == "api.osv.dev" }
func dialPublic(ctx context.Context, address string, resolve func(context.Context, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || port != "443" || !sourceHost(host) {
		return nil, ErrUntrusted
	}
	addresses, e := resolve(ctx, host)
	if e != nil || len(addresses) == 0 || len(addresses) > 64 {
		return nil, ErrUnavailable
	}
	for _, a := range addresses {
		if !publicAddress(a) {
			return nil, ErrUntrusted
		}
	}
	// The admitted address, not its re-resolved hostname, is the actual dial.
	for _, a := range addresses {
		connection, e := dial(ctx, "tcp", netip.AddrPortFrom(a.Unmap(), 443).String())
		if e == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, ErrUnavailable
}
func newPublicHTTP() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, MaxResponseHeaderBytes: 1 << 20, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return dialPublic(ctx, address, func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}, d.DialContext)
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func fetchPublic(ctx context.Context, b *Budget, s requestSpec, out io.Writer) (responseEvidence, error) {
	client := newPublicHTTP()
	defer client.CloseIdleConnections()
	return fetchUsing(ctx, b, s, out, client)
}
func fetchUsing(ctx context.Context, b *Budget, s requestSpec, out io.Writer, client *http.Client) (responseEvidence, error) {
	if ctx == nil || b == nil || out == nil || client == nil {
		return responseEvidence{}, ErrUnavailable
	}
	destination, e := s.url()
	if e != nil {
		return responseEvidence{}, e
	}
	if b.Deadline.IsZero() {
		b.Deadline = time.Now().Add(15 * time.Minute)
	}
	ctx, cancel := context.WithDeadline(ctx, b.Deadline)
	defer cancel()
	redirects := 0
	for attempt := 0; attempt < 3; attempt++ {
		if e := ctx.Err(); e != nil {
			return responseEvidence{}, e
		}
		if b.Requests >= 10000 || b.HTTPBytes >= 2<<30 {
			return responseEvidence{}, ErrLimit
		}
		b.Requests++
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, destination.String(), nil)
		if e != nil {
			return responseEvidence{}, ErrUntrusted
		}
		request.Header.Set("User-Agent", "PackTrace/experimental")
		request.Header.Set("Accept-Encoding", "identity")
		if s.etag != "" {
			request.Header.Set("If-None-Match", s.etag)
		}
		response, e := client.Do(request)
		if e != nil {
			if ctx.Err() != nil {
				return responseEvidence{}, ctx.Err()
			}
			continue
		}
		acceptedEncoding := response.Header.Get("Content-Encoding") == "" || response.Header.Get("Content-Encoding") == "identity"
		var target io.Writer = io.Discard
		limit := uint64(64 << 10)
		if response.StatusCode == 200 && acceptedEncoding {
			target = out
			switch s.kind {
			case requestArchive:
				limit = 1 << 30
			case requestChanges:
				limit = 256 << 20
			case requestRecord:
				limit = 4 << 20
			default:
				limit = 512 << 10
			}
		}
		size, readErr := readHTTPBody(ctx, b, response.Body, limit, target)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			return responseEvidence{}, errors.Join(readErr, closeErr)
		}
		if !acceptedEncoding {
			return responseEvidence{}, ErrUntrusted
		}
		evidence := responseEvidence{status: response.StatusCode, bytes: size, etag: response.Header.Get("ETag"), generation: response.Header.Get("X-Goog-Generation"), conditional: s.etag != ""}
		if s.generation != "" && evidence.generation != "" && evidence.generation != s.generation {
			return responseEvidence{}, ErrUntrusted
		}
		if response.StatusCode == 304 && evidence.etag != "" && evidence.etag != s.etag {
			return responseEvidence{}, ErrUntrusted
		}
		switch response.StatusCode {
		case 200:
			return evidence, nil
		case 304:
			if s.etag != "" {
				return evidence, nil
			}
			return responseEvidence{}, ErrUntrusted
		case 404:
			if s.kind == requestRecord {
				return evidence, nil
			}
			return responseEvidence{}, ErrUnavailable
		case 301, 302, 303, 307, 308:
			redirects++
			next, e := destination.Parse(response.Header.Get("Location"))
			original, _ := s.url()
			if e != nil || redirects > 3 || next.User != nil || next.Fragment != "" || next.Scheme != "https" || next.Port() != "" && next.Port() != "443" || !sourceHost(next.Hostname()) || next.Hostname() != original.Hostname() || next.EscapedPath() != original.EscapedPath() || next.RawQuery != original.RawQuery {
				return responseEvidence{}, ErrUntrusted
			}
			destination = next
		case 429, 500, 502, 503, 504:
			continue
		default:
			return responseEvidence{}, ErrUnavailable
		}
	}
	return responseEvidence{}, ErrUnavailable
}
func readHTTPBody(ctx context.Context, b *Budget, input io.Reader, limit uint64, out io.Writer) (uint64, error) {
	var used uint64
	buffer := make([]byte, 64<<10)
	for {
		if e := ctx.Err(); e != nil {
			return used, e
		}
		if b.HTTPBytes >= 2<<30 {
			return used, ErrLimit
		}
		window := uint64(len(buffer))
		if left := (2 << 30) - b.HTTPBytes; window > left {
			window = left
		}
		if left := limit - used + 1; window > left {
			window = left
		}
		n, e := input.Read(buffer[:window])
		if n < 0 || n > int(window) {
			return used, ErrCorrupt
		}
		b.HTTPBytes += uint64(n)
		used += uint64(n)
		if used > limit {
			return used, ErrLimit
		}
		if n > 0 {
			written, writeErr := out.Write(buffer[:n])
			if writeErr != nil || written != n {
				return used, ErrUnavailable
			}
		}
		if errors.Is(e, io.EOF) {
			return used, nil
		}
		if e != nil {
			return used, ErrUnavailable
		}
		if n == 0 {
			return used, io.ErrNoProgress
		}
	}
}
