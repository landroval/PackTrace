package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

// Deliberately opt-in: the unchanged frozen miniature fixtures are authored by
// check_metadata_capacity.py. This does not execute 1,000 payload comparisons or
// claim B6/native/performance qualification. It crosses real source acquisition,
// production frame encoding/decoding and original admission, not test substitutes.
func TestOfflineCompactPolicyCapacity(t *testing.T) {
	base := os.Getenv("PACKTRACE_METADATA_CAPACITY")
	if base == "" {
		t.Skip("requires owned check_metadata_capacity.py fixture")
	}
	dir := filepath.Join(base, "checked-1000")
	name := filepath.Join(dir, "prepared", "policy.json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 392346 {
		t.Fatalf("frozen policy changed: %d", len(raw))
	}
	if _, err := integrityscan.ParsePolicy(raw); err == nil {
		t.Fatal("legacy source cap changed")
	}
	var p integrityscan.Policy
	if json.Unmarshal(raw, &p) != nil || integrityscan.ValidatePolicy(p) != nil || len(p.References) != 1000 {
		t.Fatal("frozen semantics")
	}
	rows := make([][6]string, 0, len(p.References))
	for _, r := range p.References {
		if r.Location != r.LockKey || r.Classification != "unknown" || r.Context != "none" {
			t.Fatal("not losslessly representable")
		}
		rows = append(rows, [6]string{r.Location, r.Name, r.Version, r.Origin, r.ExpectedSRI, r.Archive})
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "references")
	fields["referenceTable"], _ = json.Marshal(map[string]any{"format": "same-location-lockkey-v1", "classification": "unknown", "context": "none", "rows": rows})
	compact, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := integrityscan.ParsePolicy(compact)
	if err != nil || !reflect.DeepEqual(parsed, p) {
		t.Fatal("ordered exact expansion", err)
	}
	// Preserve the actual legacy source and target originals; new explicitly
	// selected source, new source pin. No truncation, substitution or new grants.
	compactName := filepath.Join(dir, "prepared", "compact-policy.json")
	f, err := os.OpenFile(compactName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(compact)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	sum := sha256.Sum256(compact)
	pin := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	target := filepath.Join(dir, "target")
	obs, err := integrityscan.AcquirePolicyPinned(context.Background(), compactName, target, pin)
	if err != nil || obs.SourceHash != pin || obs.MatchedOperatorDigest != pin || !reflect.DeepEqual(obs.Policy, p) {
		t.Fatal("production source admission", err)
	}
	plan, err := integrityscan.Configure(cli.ScanArgumentRequest{PolicyPath: compactName, TrustedPolicyDigest: pin, Checks: cli.ArgumentCheckIntegrity, Manager: "auto", Output: "-"}, obs.Policy)
	if err != nil {
		t.Fatal(err)
	}
	lengths := map[string]int{}
	for _, frame := range []struct {
		kind string
		data any
	}{
		{"policy", obs},
		{"config", scanConfig{Stage: "acquire", Target: target, PolicyPath: compactName, PolicyHash: pin, Plan: &plan, Intelligence: &scanIntelligenceConfig{}}},
	} {
		var wire bytes.Buffer
		if err := newChannel(bytes.NewReader(nil), &wire, &traffic{}).send(frame.kind, frame.data); err != nil {
			t.Fatal("production envelope", err)
		}
		lengths[frame.kind] = wire.Len()
		env, err := newChannel(bytes.NewReader(wire.Bytes()), &bytes.Buffer{}, &traffic{}).receive()
		if err != nil {
			t.Fatal(err)
		}
		if frame.kind == "policy" {
			var got integrityscan.PolicyObservation
			if decodeCheckedObject(env.Data, &got) != nil || !reflect.DeepEqual(got, obs) || integrityscan.ValidatePolicy(got.Policy) != nil {
				t.Fatal("policy frame round trip")
			}
		} else {
			var got scanConfig
			if decodeCheckedObject(env.Data, &got) != nil || !reflect.DeepEqual(got.Plan, &plan) || integrityscan.ValidatePlanPolicy(*got.Plan) != nil {
				t.Fatal("config round trip")
			}
		}
	}
	root, err := nativefs.OpenRoot(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: p.Manager, ExplicitManager: true, RetainIntegrityOriginals: true})
	closeErr = root.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	original := projectinventory.PrivateOriginal(inv)
	if !inv.Complete || projectinventory.ValidateOriginalBytes(original) != nil {
		t.Fatal("original native receipts invalid")
	}
	encoded, _ := json.Marshal(original)
	rowCount := len(original.Model.Observations) + len(original.Model.Evidence) + len(original.OriginalInputs)
	envelopeJSON, _ := json.Marshal(envelope{Version: 1, Seq: 1, Job: 1, Type: "bun-original", Data: encoded})
	var b scanPolicyMaterialBuffer
	var wire bytes.Buffer
	sent, err := b.emitOriginal(newChannel(bytes.NewReader(nil), &wire, &traffic{}).send, inv)
	if rowCount != 6006 || len(envelopeJSON)+1 <= maxMessage || !sent || err != nil || b.originalRows != 3006 {
		t.Fatalf("compact admission: rows=%d legacyEnvelope=%d sent=%v err=%v", rowCount, len(envelopeJSON)+1, sent, err)
	}
	env, err := newChannel(bytes.NewReader(wire.Bytes()), &bytes.Buffer{}, &traffic{}).receive()
	if err != nil || env.Type != "npm-root-original" {
		t.Fatal("compact transport", err)
	}
	var v projectinventory.CompactNPMRoot
	if decodeCheckedObject(env.Data, &v) != nil {
		t.Fatal("compact decode")
	}
	var parent scanPolicyMaterialBuffer
	admitted, err := parent.addCompactNPM(v)
	pub := projectinventory.PortableMatching(inv)
	pub.OriginalClaims = &admitted
	if err != nil || projectinventory.ValidateOriginalClaims(pub) != nil || parent.originalRows != b.originalRows || parent.bytes != b.bytes {
		t.Fatal("independent parent admission", err)
	}
	var legacy scanPolicyMaterialBuffer
	if legacy.addOriginal(original) == nil {
		t.Fatal("parent original row gate changed")
	}
	facts := map[string]any{"legacyPolicyBytes": len(raw), "compactPolicyBytes": len(compact), "references": len(p.References), "exactOrderedExpansion": true, "sourceAdmitted": true, "pin": pin, "normalizedFrameLFBytes": lengths, "originalRows": rowCount, "originalEnvelopeLFBytes": len(envelopeJSON) + 1, "originalAdmitted": true, "compactOriginalRows": b.originalRows, "compactOriginalBytes": b.bytes, "compactOriginalFrameLFBytes": wire.Len(), "firstRemainingGate": "metadata admission complete; payload comparison not run here", "wholeIntegrityCompleted": false, "scope": "metadata-only, no 1000-package payload comparison"}
	saveCapacity(t, filepath.Join(dir, "compact-capacity.json"), facts)
	t.Logf("%+v", facts)
}
