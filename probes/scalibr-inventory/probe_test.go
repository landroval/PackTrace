package inventoryprobe

import (
	"strings"
	"testing"
)

// These check the probe's evidence capture, not product compatibility.
func TestProbeCapture(t *testing.T) {
	c := Case{ID: "capture", Group: "self", Extractor: "manifest", Path: "node_modules/a/package.json", Content: `{"name":"a","version":"1.2.3","dependencies":{"b":"^2.0.0"}}`}
	o := Observe(c)
	if !o.Selected || o.Error != "" || len(o.Packages) != 1 {
		t.Fatalf("lost extraction outcome: %+v", o)
	}
	p := o.Packages[0]
	if p.Name != "a" || p.Version != "1.2.3" || p.Path != c.Path {
		t.Fatalf("lost identity/location: %+v", p)
	}
	if o.InputSHA256 == "" || o.Module != Module || o.EvidenceClass != "extractor-output-not-installation-proof" {
		t.Fatalf("missing provenance/limitation: %+v", o)
	}
}

func TestProbeBoundedReader(t *testing.T) {
	c := Case{ID: "budget", Extractor: "manifest", Path: "package.json", Content: strings.Repeat(" ", MaxInputBytes+1)}
	o := Observe(c)
	if o.Error != "probe input exceeds 2 MiB" || len(o.Packages) != 0 {
		t.Fatalf("oversized input reached extractor: %+v", o)
	}
}

func TestProbePartialInventory(t *testing.T) {
	o := Observe(Case{ID: "partial", Extractor: "bun", Path: "bun.lock", Content: `{"lockfileVersion":1,"packages":{"a":["a@1.0.0"],"bad":[]}}`})
	if len(o.Packages) != 1 || o.Error == "" {
		t.Fatalf("lost partial inventory or error: %+v", o)
	}
}

func TestProbeNoManifestInference(t *testing.T) {
	o := Observe(Case{ID: "declaration", Extractor: "manifest", Path: "package.json", Content: `{"name":"root","version":"1.0.0","dependencies":{"absent":"^2.0.0"}}`})
	if len(o.Packages) != 1 || o.Packages[0].Name != "root" {
		t.Fatalf("dependency inference unexpectedly enabled: %+v", o)
	}
}
