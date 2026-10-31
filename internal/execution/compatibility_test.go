package execution

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"packtrace/internal/inspect"
)

func TestSupervisedPortableSemanticVariants(t *testing.T) {
	var packet map[string]json.RawMessage
	if json.Unmarshal([]byte(fixture), &packet) != nil {
		t.Fatal("fixture")
	}
	var ads []json.RawMessage
	_ = json.Unmarshal(packet["advisories"], &ads)
	ad := string(ads[0])
	lock := string(packet["lockfile"])
	locks := []string{lock, `{"lockfileVersion":3,"packages":{"":{}}}`, `{"lockfileVersion":3,"packages":{"node_modules/owned":{"version":"1.2.3"}}}`, strings.Replace(lock, `"name":"owned"`, `"name":null`, 1), strings.Replace(lock, `"version":"1.2.3"`, `"version":"INVALID"`, 1), strings.Replace(lock, `"version":"1.2.3"`, `"version":null`, 1), strings.Replace(lock, `"version":"1.2.3"`, `"version":"1.2.3","link":true`, 1)}
	advisories := []string{ad, `42`, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[]}`, `{"id":"OWNED","modified":"2026-01-01T00:00:00Z","affected":[null]}`, strings.Replace(ad, `"modified":`, `"schema_version":"99.0.0","modified":`, 1), strings.Replace(ad, `"modified":`, `"withdrawn":null,"modified":`, 1), strings.Replace(ad, `"versions":["1.2.3"]`, `"versions":["INVALID",null]`, 1), strings.Replace(ad, `"versions":["1.2.3"]`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`, 1)}
	for _, profile := range []string{"explicit-only", "npm-lock-v2-v3"} {
		for li, l := range locks {
			for ai, a := range advisories {
				input := `{"lockfile":` + l + `,"advisories":[` + a + `]}`
				want, we := inspect.ReadBatchProfile(strings.NewReader(input), profile)
				got, e := RunBatch(context.Background(), strings.NewReader(input), profile)
				if (we == nil) != (e == nil) || (e == nil && (!got.Usable || !reflect.DeepEqual(want, got.Result))) {
					t.Fatalf("profile=%s lock=%d advisory=%d result mismatch %v/%v\n%+v\n%+v", profile, li, ai, we, e, want, got)
				}
			}
		}
	}
}
