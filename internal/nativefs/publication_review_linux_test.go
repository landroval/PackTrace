//go:build linux && (amd64 || arm64)

package nativefs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicationPlanFailedBindingConsumesAttempt(t *testing.T) {
	f := newPlanFixture(t)
	p := f.plan(t, filepath.Join(f.base, "output", "report"))
	original := p.publication.ctx
	ctx, cancel := context.WithCancel(original)
	cancel()
	p.publication.ctx = ctx
	if pub, err := p.Begin(); err == nil || pub != nil {
		t.Fatal("cancelled binding began publication")
	}
	p.publication.ctx = original
	if pub, err := p.Begin(); err == nil || pub != nil {
		if pub != nil {
			pub.Close()
		}
		t.Fatal("failed binding did not consume single attempt")
	}
	entries, err := os.ReadDir(filepath.Join(f.base, "output"))
	if err != nil || len(entries) != 0 {
		t.Fatal("failed admission created a temporary")
	}
}

func TestPublicationRejectsObservedHardlinkBeforeWriting(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"target/deep", "state", "reference", "output"} {
		if os.MkdirAll(filepath.Join(base, name), 0700) != nil {
			t.Fatal("owned directories")
		}
	}
	f := openPlanFixture(t, base)
	p := f.plan(t, filepath.Join(base, "output", "report"))
	pub, err := p.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	linked := filepath.Join(base, "target", "deep", "linked")
	if os.Link(filepath.Join(base, "output", pub.temp), linked) != nil {
		t.Fatal("authored link mutation")
	}
	if n, err := pub.Write([]byte("approved report bytes")); err == nil || n != 0 {
		t.Fatal("publication wrote through an observed unexpected hardlink")
	}
	data, err := os.ReadFile(linked)
	if err != nil || len(data) != 0 {
		t.Fatal("linked target received bytes before refusal")
	}
	if pub.Commit() == nil {
		t.Fatal("poisoned publication committed")
	}
}
