package intelstore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGlobalCSVAcceptsPublicOSVIDColonWithoutPathAuthority(t *testing.T) {
	var got changeRow
	_, e := walkChanges(context.Background(), strings.NewReader("2026-11-01T00:00:00Z,AlmaLinux/ALSA-2026:1234\n"), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), func(row changeRow) error { got = row; return nil })
	if e != nil || got.ID != "ALSA-2026:1234" {
		t.Fatal("valid unrelated ecosystem prevents global change qualification", e)
	}
	u, e := (requestSpec{kind: requestRecord, id: got.ID}).url()
	if e != nil || u.Hostname() != "api.osv.dev" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("public ID became URL authority", e)
	}
}
