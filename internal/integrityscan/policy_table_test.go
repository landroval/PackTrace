package integrityscan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func tableSource(t *testing.T, p Policy) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		t.Fatal("policy")
	}
	rows := make([][6]string, 0, len(p.References))
	classification, context := "unknown", "none"
	for _, r := range p.References {
		if r.Location != r.LockKey {
			t.Fatal("unequal lock key")
		}
		classification, context = r.Classification, r.Context
		rows = append(rows, [6]string{r.Location, r.Name, r.Version, r.Origin, r.ExpectedSRI, r.Archive})
	}
	delete(fields, "references")
	fields["referenceTable"], err = json.Marshal(map[string]any{"format": "same-location-lockkey-v1", "classification": classification, "context": context, "rows": rows})
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReferenceTableExpansion(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	r := p.References[0]
	r.Location, r.LockKey, r.Name, r.Archive = "node_modules/second", "node_modules/second", "second", "second.tgz"
	p.References = append(p.References, r)
	raw := tableSource(t, p)
	got, err := ParsePolicy(raw)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("ordered lossless expansion: %v %+v", err, got)
	}
	// Normalized policy/config marshaling stays legacy; no second authority retained.
	wire, _ := json.Marshal(got)
	round, err := ParsePolicy(wire)
	if err != nil || !reflect.DeepEqual(round, p) || strings.Contains(string(wire), "referenceTable") {
		t.Fatal("normalized round trip", err)
	}
	p.References = []Reference{}
	got, err = ParsePolicy(tableSource(t, p))
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("explicit empty table", err)
	}
}

func TestReferenceTableRejectsMalformed(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(tableSource(t, p))
	var root map[string]json.RawMessage
	_ = json.Unmarshal([]byte(raw), &root)
	table := string(root["referenceTable"])
	var tableFields map[string]json.RawMessage
	_ = json.Unmarshal(root["referenceTable"], &tableFields)
	for key, value := range tableFields {
		for _, mode := range []string{"missing", "null", "alias", "duplicate"} {
			t.Run(key+"/"+mode, func(t *testing.T) {
				q := map[string]json.RawMessage{}
				for k, v := range tableFields {
					q[k] = v
				}
				switch mode {
				case "missing":
					delete(q, key)
				case "null":
					q[key] = json.RawMessage(`null`)
				case "alias":
					q[strings.ToUpper(key[:1])+key[1:]] = value
					delete(q, key)
				}
				b, _ := json.Marshal(q)
				if mode == "duplicate" {
					token, _ := json.Marshal(key)
					b = []byte(strings.Replace(string(b), string(token)+":", string(token)+":"+string(value)+","+string(token)+":", 1))
				}
				if _, err := ParsePolicy([]byte(strings.Replace(raw, table, string(b), 1))); err == nil {
					t.Fatal("noncanonical table admitted")
				}
			})
		}
	}
	delete(root, "referenceTable")
	missing, _ := json.Marshal(root)
	if _, err := ParsePolicy(missing); err == nil {
		t.Fatal("no encoding admitted")
	}
	if _, err := ParsePolicy(append([]byte(raw), bytes.Repeat([]byte(" "), MaxPolicyBytes)...)); err == nil {
		t.Fatal("source byte ceiling changed")
	}
	mutations := []string{
		`null`, `{}`, strings.Replace(table, `same-location-lockkey-v1`, `v2`, 1),
		strings.Replace(table, `"format":`, `"Format":`, 1),
		strings.Replace(table, `"format":`, `"unknown":0,"format":`, 1),
		strings.Replace(table, `"context":"none"`, `"context":null`, 1),
		strings.Replace(table, `"context":"none"`, `"context":"none","context":"none"`, 1),
		strings.Replace(table, `"classification":"private"`, `"classification":"*"`, 1),
		`{"format":"same-location-lockkey-v1","classification":"unknown","context":"none","rows":null}`,
	}
	for _, rows := range []string{`{}`, `[null]`, `[[]]`, `[["a"]]`, `[["a","b","c","d","e","f","g"]]`, `[["a","b","c","d","e",null]]`, `[["a","b","c","d","e",1]]`, `[` + strings.Repeat(`[],`, 20000) + `[]]`} {
		mutations = append(mutations, `{"format":"same-location-lockkey-v1","classification":"unknown","context":"none","rows":`+rows+`}`)
	}
	for i, m := range mutations {
		bad := []byte(strings.Replace(raw, table, m, 1))
		if _, err := ParsePolicy(bad); err == nil {
			t.Fatalf("mutation %d admitted: %s", i, bad)
		}
	}
	for _, bad := range []string{
		strings.Replace(raw, `"referenceTable":`, `"references":[],"referenceTable":`, 1),
		strings.Replace(raw, `"referenceTable":`, `"ReferenceTable":`, 1),
		strings.Replace(raw, `"referenceTable":`+table, `"references":null`, 1),
	} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Fatal("mixed/alias/null admitted")
		}
	}
	// Expanded semantics (including duplicate paths) are still checked.
	p.References = append(p.References, p.References[0])
	if _, err := ParsePolicy(tableSource(t, p)); err == nil {
		t.Fatal("duplicate expansion admitted")
	}
}

func TestReferenceTableNativePinAndReread(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("owned native Linux case; not qualification")
	}
	root, name, p := ownedFixture(t)
	raw := tableSource(t, p)
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pin := sourceSRI(raw)
	obs, err := AcquirePolicyPinned(context.Background(), name, root, pin)
	if err != nil || obs.SourceHash != pin || obs.MatchedOperatorDigest != pin || !reflect.DeepEqual(obs.Policy, p) {
		t.Fatal("actual compact source admission", err)
	}
	legacy, _ := json.Marshal(p)
	if _, err := AcquirePolicyPinned(context.Background(), name, root, sourceSRI(legacy)); err == nil {
		t.Fatal("normalized bytes substituted for source pin")
	}
	plan, _ := fixturePlan(t, name, p) // helper rewrites source; restore compact bytes.
	plan.TrustedPolicyDigest = pin
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	records := 0
	_, err = Acquire(context.Background(), root, filepath.Dir(name), pin, plan, func(r Record) error { records++; return ValidateRecord(plan, r, pin) })
	if err != nil || records != 1 {
		t.Fatal("compact native comparison", err, records)
	}
	changed := append(append([]byte{}, raw...), ' ')
	if err := os.WriteFile(name, changed, 0600); err != nil {
		t.Fatal(err)
	}
	records = 0
	_, err = Acquire(context.Background(), root, filepath.Dir(name), pin, plan, func(Record) error { records++; return nil })
	if err == nil || records != 0 {
		t.Fatal("changed external source reached comparison")
	}
}
