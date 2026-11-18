package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"packtrace/internal/cli"
	"packtrace/internal/integrity"
	"packtrace/internal/integrityscan"
	"packtrace/internal/nativefs"
	"packtrace/internal/projectinventory"
)

// Opt-in bounded local check, not B6 qualification. Source fixture files remain
// outside the repository. No subprocess, target execution, or network access.
func TestOfflineMetadataCapacity(t *testing.T) {
	base := os.Getenv("PACKTRACE_METADATA_CAPACITY")
	if base == "" {
		t.Skip("requires owned check_metadata_capacity.py fixture")
	}
	for _, name := range []string{"b6-original-1000", "checked-2", "checked-1000"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, name)
			target := filepath.Join(dir, "target")
			root, err := nativefs.OpenRoot(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := projectinventory.Collect(context.Background(), root, projectinventory.Options{Profile: "npm@10.9.4", ExplicitManager: true, RetainIntegrityOriginals: true})
			closeErr := root.Close()
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			original := projectinventory.PrivateOriginal(inv)
			originalErr := projectinventory.ValidateOriginalBytes(original)
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			raw := 0
			for _, row := range original.OriginalInputs {
				raw += len(row.Bytes)
			}
			rows := len(original.Model.Observations) + len(original.Model.Evidence) + len(original.OriginalInputs)
			var frame bytes.Buffer
			ch := newChannel(bytes.NewReader(nil), &frame, &traffic{})
			var material scanPolicyMaterialBuffer
			// Preserve the frozen legacy regression independently of the new
			// compact-profile admission and supervised tests.
			sent, err := material.emitLegacyOriginal(ch.send, inv)
			if err != nil {
				t.Fatal(err)
			}
			policyBytes, err := os.ReadFile(filepath.Join(dir, "prepared", "policy.json"))
			if err != nil {
				t.Fatal(err)
			}
			policy, policyErr := integrityscan.ParsePolicy(policyBytes)
			// Decode only for diagnostics after actual parser rejection. Never acquire
			// or grant a plan from a policy that failed product admission.
			var authored integrityscan.Policy
			if err := json.Unmarshal(policyBytes, &authored); err != nil {
				t.Fatal(err)
			}
			semanticPolicyErr := integrityscan.ValidatePolicy(authored)
			_, acquireErr := integrityscan.AcquirePolicy(context.Background(), filepath.Join(dir, "prepared", "policy.json"), target)
			if (acquireErr == nil) != (policyErr == nil) {
				t.Fatal("policy source admission disagrees with parser")
			}
			referenceJSON, _ := json.Marshal(authored.References)
			checkedArchives := 0
			lockBytes, e := os.ReadFile(filepath.Join(target, "package-lock.json"))
			if e != nil {
				t.Fatal(e)
			}
			var lock struct {
				Packages map[string]struct{ Name, Version, Resolved, Integrity string }
			}
			if e = json.Unmarshal(lockBytes, &lock); e != nil {
				t.Fatal(e)
			}
			for _, ref := range authored.References {
				row, ok := lock.Packages[ref.LockKey]
				if !ok || row.Name != ref.Name || row.Version != ref.Version || row.Resolved != ref.Origin || row.Integrity != ref.ExpectedSRI {
					t.Fatal("reference not bound to source lock tuple")
				}
				data, e := os.ReadFile(filepath.Join(dir, "prepared", ref.Archive))
				if e != nil {
					t.Fatal(e)
				}
				check, e := integrity.CheckReferenceDigestSet(context.Background(), ref.ExpectedSRI, bytes.NewReader(data), int64(len(data)))
				if e != nil || check.State != integrity.DigestMatch || check.BytesRead != int64(len(data)) {
					t.Fatalf("archive digest not matched: %+v %v", check, e)
				}
				checkedArchives++
			}
			prefixMax := 0
			prefixBytes := 0
			for n := 0; n <= len(authored.References); n++ {
				p := authored
				p.References = authored.References[:n]
				b, e := json.Marshal(p)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = integrityscan.ParsePolicy(b); e == nil {
					prefixMax = n
					prefixBytes = len(b)
				}
			}
			facts := map[string]any{"fixture": name, "inventoryComplete": inv.Complete, "observations": len(original.Model.Observations), "evidence": len(original.Model.Evidence), "inputs": len(original.OriginalInputs), "rawBytes": raw, "originalRows": rows, "originalJSONBytes": len(encoded), "originalValid": originalErr == nil, "originalEmitted": sent, "originalFrameBytes": frame.Len(), "policyBytes": len(policyBytes), "policyAdmitted": policyErr == nil, "policySemanticallyValid": semanticPolicyErr == nil, "references": len(authored.References), "maxAdmittedReferencePrefix": prefixMax, "maxAdmittedReferencePrefixBytes": prefixBytes}
			// Channel-only counterfactual distinguishes its later frame limit from
			// emitOriginal's earlier row branch; this cannot authorize acquisition.
			var diagnostic bytes.Buffer
			frameErr := newChannel(bytes.NewReader(nil), &diagnostic, &traffic{}).send("bun-original", original)
			envelopeBytes, _ := json.Marshal(envelope{Version: 1, Seq: 1, Job: 1, Type: "bun-original", Data: encoded})
			if prefixMax < len(authored.References) {
				p := authored
				p.References = authored.References[:prefixMax+1]
				b, _ := json.Marshal(p)
				facts["firstRejectedReferencePrefixBytes"] = len(b)
			}
			facts["referenceArrayJSONBytes"] = len(referenceJSON)
			facts["checkedArchives"] = checkedArchives
			facts["sourcePolicyAdmitted"] = acquireErr == nil
			facts["counterfactualFrameAccepted"] = frameErr == nil
			facts["counterfactualEnvelopeLFBytes"] = len(envelopeBytes) + 1
			if name == "checked-2" {
				if len(authored.References) != 2 || frameErr != nil || !inv.Complete || originalErr != nil || !sent || policyErr != nil {
					t.Fatalf("small admission: %+v", facts)
				}
				// Replay exact on-wire original into actual product validator.
				receiver := newChannel(bytes.NewReader(frame.Bytes()), &bytes.Buffer{}, &traffic{})
				env, e := receiver.receive()
				if e != nil {
					t.Fatal(e)
				}
				var replay projectinventory.Result
				if e = decode(env.Data, &replay); e != nil {
					t.Fatal(e)
				}
				if e = projectinventory.ValidateOriginalBytes(replay); e != nil {
					t.Fatal(e)
				}
				var parentMaterial scanPolicyMaterialBuffer
				if e = parentMaterial.addOriginal(replay); e != nil {
					t.Fatal(e)
				}
				sum := sha256.Sum256(policyBytes)
				hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
				plan := integrityscan.Plan{PolicyFile: "policy.json", TrustedPolicyDigest: hash, Manager: policy.Manager, ExplicitManager: true, Policy: policy, Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity}
				var records []integrityscan.Record
				var public projectinventory.PublicInventory
				summary, e := integrityscan.AcquireWithInventory(context.Background(), target, filepath.Join(dir, "prepared"), hash, plan, func(r integrityscan.Record) error {
					if !integrityscan.ValidateIntegrityScopeReceipt(plan, r, hash) {
						t.Fatal("unbound scope receipt")
					}
					material.retainIntegrityScope(&r)
					if r.IntegrityScope == nil {
						b, _ := json.Marshal(r)
						t.Fatalf("scope witness lost: %s", b)
					}
					// Same finite-array normalization as scan.go emitRecord.
					if r.Assessment.Differences == nil {
						r.Assessment.Differences = []integrity.Difference{}
					}
					if r.Assessment.Gaps == nil {
						r.Assessment.Gaps = []integrity.Gap{}
					}
					if r.Assessment.Contexts == nil {
						r.Assessment.Contexts = []integrity.ScopedContext{}
					}
					var wire bytes.Buffer
					if e := newChannel(bytes.NewReader(nil), &wire, &traffic{}).send("instance", r); e != nil {
						t.Fatal(e)
					}
					env, e := newChannel(bytes.NewReader(wire.Bytes()), &bytes.Buffer{}, &traffic{}).receive()
					if e != nil {
						t.Fatal(e)
					}
					var admitted integrityscan.Record
					if e = decode(env.Data, &admitted); e != nil {
						t.Fatal(e)
					}
					if e = integrityscan.ValidateRecord(plan, admitted, hash); e != nil {
						t.Fatal(e)
					}
					if !integrityscan.ValidateIntegrityScopeReceipt(plan, admitted, hash) {
						t.Fatal("replayed scope invalid")
					}
					if e = parentMaterial.addIntegrityScope(admitted.IntegrityScope); e != nil {
						t.Fatal(e)
					}
					records = append(records, admitted)
					return nil
				}, func(r projectinventory.Result) error { public = projectinventory.PortableMatching(r); return nil })
				if e != nil {
					t.Fatal(e)
				}
				public.OriginalClaims = &replay
				if e = projectinventory.ValidateOriginalClaims(public); e != nil {
					t.Fatal(e)
				}
				if material.bytes != parentMaterial.bytes || material.originalRows != parentMaterial.originalRows {
					t.Fatal("parent accounting differs")
				}
				report := integrityscan.BuildReportWithPolicy(plan, records, summary, integrityscan.Resources{}, false, false, &public, nil, nil, nil, false, time.Now().UTC())
				completed := false
				for _, c := range report.Coverage {
					if c.Check == "integrity" && c.Outcome == "completed" {
						completed = true
					}
				}
				if !completed || report.Findings != 0 || len(records) != 2 {
					t.Fatalf("small whole scope not complete: %+v", report)
				}
				facts["wholeIntegrityCompleted"] = completed
				facts["retainedPrivateRows"] = material.originalRows
				facts["retainedPrivateBytes"] = material.bytes
				saveCapacity(t, filepath.Join(dir, "accepted-records.json"), records)
				saveCapacity(t, filepath.Join(dir, "report.json"), report)
			} else {
				if name == "b6-original-1000" {
					sum := sha256.Sum256(policyBytes)
					hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
					plan := integrityscan.Plan{PolicyFile: "policy.json", Manager: policy.Manager, Policy: policy, Checks: cli.ArgumentCheckIntegrity, FailOn: cli.ArgumentCheckIntegrity}
					var public projectinventory.PublicInventory
					summary, e := integrityscan.AcquireWithInventory(context.Background(), target, filepath.Join(dir, "prepared"), hash, plan, func(r integrityscan.Record) error { t.Fatal("no authored references, unexpected record"); return nil }, func(r projectinventory.Result) error { public = projectinventory.PortableMatching(r); return nil })
					if e != nil {
						t.Fatal(e)
					}
					report := integrityscan.BuildReportWithPolicy(plan, nil, summary, integrityscan.Resources{}, false, false, &public, nil, nil, nil, false, time.Now().UTC())
					for _, c := range report.Coverage {
						if c.Check == "integrity" {
							facts["wholeIntegrityCompleted"] = c.Outcome == "completed"
							if c.Outcome == "completed" {
								t.Fatal("missing references granted whole integrity")
							}
						}
					}
					saveCapacity(t, filepath.Join(dir, "report.json"), report)
				}
				if rows != 6006 || len(original.Model.Observations) != 3001 || len(original.Model.Evidence) != 2003 || len(original.OriginalInputs) != 1002 {
					t.Fatal("frozen 1000-instance row contract changed")
				}
				if frameErr != errLimit || frame.Len() != 0 || material.bytes != 0 || material.originalRows != 0 {
					t.Fatal("expected first-row-branch abstention and independent frame limit")
				}
				if !inv.Complete || originalErr != nil || sent || rows <= integrityscan.MaxPolicyMaterials {
					t.Fatalf("expected row refusal: %+v", facts)
				}
				if name == "checked-1000" && (len(authored.References) != 1000 || len(referenceJSON) <= integrityscan.MaxPolicyBytes || prefixMax != 667 || policyErr == nil || semanticPolicyErr != nil) {
					t.Fatalf("expected policy byte refusal: %+v", facts)
				}
			}
			saveCapacity(t, filepath.Join(dir, "original.json"), original)
			saveCapacity(t, filepath.Join(dir, "capacity.json"), facts)
			t.Logf("%+v", facts)
		})
	}
}

func saveCapacity(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, e := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}
