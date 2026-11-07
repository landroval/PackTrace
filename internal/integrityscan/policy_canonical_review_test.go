package integrityscan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewCanonicalPolicyKeys(t *testing.T) {
	p, err := ParsePolicy([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	p.FailOn = []string{"integrity"}
	p.NPMRegistry = "https://registry.npmjs.org"
	p.RequirePortable = true
	p.AdvisoryCandidates = true
	p.MaxExceptionDays = 30
	p.NPMOrigins = []NPMOriginRule{{Location: "node_modules/pkg", Name: "pkg", Version: "1.0.0", Origin: npmTarballOrigin("pkg", "1.0.0")}}
	p.Exceptions = []Exception{engineException(engineMaterial())}
	b, _ := json.Marshal(p)
	if _, err := ParsePolicy(b); err != nil {
		t.Fatal("honest fixture", err)
	}
	for _, pair := range [][2]string{
		{`"failOn":["integrity"]`, `"failOn":["integrity"],"FailOn":[]`},
		{`"failOn":["integrity"]`, `"FailOn":[],"failOn":["integrity"]`},
		{`"requiredChecks":["integrity"]`, `"requiredChecks":["integrity"],"RequiredChecks":[]`},
		{`"minimumAssurance":"lockfile-consistent"`, `"minimumAssurance":"lockfile-consistent","MinimumAssurance":"lockfile-consistent"`},
		{`"version":1`, `"RequirePortable":false,"version":1`},
		{`"lockKey":`, `"LockKey":`}, {`"expectedSRI":`, `"ExpectedSRI":`},
		{`"npmOrigins":[{"location":`, `"npmOrigins":[{"Location":`},
		{`"npmOrigins":[{"location":"node_modules/pkg"`, `"npmOrigins":[{"location":"node_modules/pkg","Location":"node_modules/pkg"`},
		{`"owner":`, `"Owner":`}, {`"project":`, `"Project":`},
		{`"failOn":["integrity"]`, `"failOn":null`},
		{`"requireHardMemoryLimit":false`, `"requireHardMemoryLimit":null`},
		{`"version":1`, `"requirePortable":null,"version":1`},
		{`"version":1`, `"unknown":false,"version":1`},
		{`"lockKey":"node_modules/pkg"`, `"lockKey":null`},
		{`"npmOrigins":[{"location":"node_modules/pkg"`, `"npmOrigins":[{"location":null`},
	} {
		t.Run(pair[1], func(t *testing.T) {
			raw := strings.Replace(string(b), pair[0], pair[1], 1)
			if raw == string(b) {
				t.Fatal("mutation did not change fixture", pair[0])
			}
			if !policyPinMatches(context.Background(), sourceSRI([]byte(raw)), []byte(raw)) {
				t.Fatal("pinned ambiguous bytes fixture did not match")
			}
			if _, err := ParsePolicy([]byte(raw)); err == nil {
				t.Fatal("pinned ambiguous/null/unknown policy admitted")
			}
		})
	}
	// Every present typed field, including optional and nested fields, rejects null
	// and alternate case; omitted optional fields remain covered by policyJSON.
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	check := func(label string, obj map[string]json.RawMessage, wrap func(map[string]json.RawMessage) []byte) {
		for key := range obj {
			for _, mode := range []string{"null", "alias", "unknown", "duplicate"} {
				t.Run(label+"/"+key+"/"+mode, func(t *testing.T) {
					q := map[string]json.RawMessage{}
					for k, v := range obj {
						q[k] = v
					}
					switch mode {
					case "null":
						q[key] = json.RawMessage(`null`)
					case "alias":
						q[strings.ToUpper(key[:1])+key[1:]] = q[key]
						delete(q, key)
					case "unknown":
						q["unknown"] = json.RawMessage(`false`)
					}
					raw := wrap(q)
					if mode == "duplicate" {
						token, _ := json.Marshal(key)
						needle := string(token) + ":" + string(obj[key])
						raw = []byte(strings.Replace(string(raw), needle, needle+","+needle, 1))
					}
					if _, err := ParsePolicy(raw); err == nil {
						t.Fatal("noncanonical typed field admitted", string(raw))
					}
				})
			}
		}
	}
	marshal := func(v any) []byte { b, _ := json.Marshal(v); return b }
	check("policy", root, func(q map[string]json.RawMessage) []byte { return marshal(q) })
	for _, field := range []string{"references", "npmOrigins", "exceptions"} {
		var rows []map[string]json.RawMessage
		_ = json.Unmarshal(root[field], &rows)
		check(field, rows[0], func(q map[string]json.RawMessage) []byte {
			r := map[string]json.RawMessage{}
			for k, v := range root {
				r[k] = v
			}
			r[field] = marshal([]any{q})
			return marshal(r)
		})
		if field == "exceptions" {
			var scope map[string]json.RawMessage
			_ = json.Unmarshal(rows[0]["scope"], &scope)
			check("scope", scope, func(q map[string]json.RawMessage) []byte {
				x := map[string]json.RawMessage{}
				for k, v := range rows[0] {
					x[k] = v
				}
				x["scope"] = marshal(q)
				r := map[string]json.RawMessage{}
				for k, v := range root {
					r[k] = v
				}
				r[field] = marshal([]any{x})
				return marshal(r)
			})
		}
	}
}
