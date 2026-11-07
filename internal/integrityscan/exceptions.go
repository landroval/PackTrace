package integrityscan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"packtrace/internal/intel"
)

const DefaultMaxExceptionDays = 30

// MaxConfiguredExceptionDays is the finite ceiling for an explicitly pinned
// policy override. Durations are elapsed UTC days, not calendar renewals.
const MaxConfiguredExceptionDays = 365

type Exception struct {
	ID         string       `json:"id"`
	Reason     string       `json:"reason"`
	Owner      string       `json:"owner"`
	ApprovedAt string       `json:"approvedAt"`
	ExpiresAt  string       `json:"expiresAt"`
	Scope      FindingScope `json:"scope"`
	Acceptance string       `json:"acceptance"`
}

func exceptionDays(p Policy) int {
	if p.MaxExceptionDays == 0 {
		return DefaultMaxExceptionDays
	}
	return p.MaxExceptionDays
}
func utcTime(s string) (time.Time, error) {
	// UTC Z only, with optional RFC3339 fractional seconds at native nanosecond
	// precision. Reject offsets, comma fractions and silent precision loss.
	if len(s) < 20 || len(s) > 30 || !strings.HasSuffix(s, "Z") {
		return time.Time{}, ErrPolicy
	}
	if len(s) > 20 {
		if s[19] != '.' || len(s) == 21 {
			return time.Time{}, ErrPolicy
		}
		for _, c := range s[20 : len(s)-1] {
			if c < '0' || c > '9' {
				return time.Time{}, ErrPolicy
			}
		}
	}
	t, e := time.Parse(time.RFC3339, s)
	if e != nil || t.Format("2006-01-02T15:04:05") != s[:19] {
		return time.Time{}, ErrPolicy
	}
	return t, nil
}
func fingerprintShape(s string) bool {
	if !strings.HasPrefix(s, "sha256-") {
		return false
	}
	b, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(s, "sha256-"))
	return e == nil && len(b) == 32 && "sha256-"+base64.StdEncoding.EncodeToString(b) == s
}
func hexSHA(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}
func scopeShape(s FindingScope) bool {
	if !fingerprintShape(s.Project) || !oneOf(s.Category, "integrity", "malicious", "vulnerability") || !oneOf(s.Class, "locked", "installed") || !text(s.Version, 256) || !text(s.Origin, 2048) || strings.ContainsAny(s.Origin, "*?\x00") || !relative(s.Instance) {
		return false
	}
	if s.Category == "integrity" {
		return canonicalNPMName(strings.ToLower(s.Package)) && !strings.ContainsAny(s.Version, "/\\:*?") && s.Rule == "integrity-drift" && s.Class == "installed" && relative(s.Path) && s.Advisory == "" && oneOf(s.Change, "modified", "missing", "added", "type-changed")
	}
	if _, err := intel.ParseSemVer(s.Version); err != nil || !canonicalNPMName(s.Package) {
		return false
	}
	return s.Rule == "osv-npm" && s.Path == "" && s.Change == "" && len(s.Advisory) <= maxLocalAdvisoryIDBytes && localAdvisoryID.MatchString(s.Advisory)
}
func validateExceptions(p Policy) error {
	if p.MaxExceptionDays < 0 || p.MaxExceptionDays > MaxConfiguredExceptionDays || len(p.Exceptions) > 64 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, x := range p.Exceptions {
		a, e := utcTime(x.ApprovedAt)
		b, f := utcTime(x.ExpiresAt)
		if !text(x.ID, 128) || !text(x.Reason, 4096) || !text(x.Owner, 256) || seen[x.ID] || !scopeShape(x.Scope) || !fingerprintShape(x.Acceptance) || e != nil || f != nil || !b.After(a) || b.Sub(a) > time.Duration(exceptionDays(p))*24*time.Hour {
			return ErrPolicy
		}
		seen[x.ID] = true
	}
	return nil
}

// canonicalFields permits omitted fields, but rejects every unknown/alternate
// tag and every present null. The final typed decoder checks value types.
func canonicalFields(m map[string]json.RawMessage, keys []string) bool {
	for k, v := range m {
		found := false
		for _, want := range keys {
			if k == want {
				found = true
				break
			}
		}
		if !found || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}

// encoding/json folds field case and accepts null into concrete zero values.
// Exception grants instead require every exact field, recursively, and no null.
func strictFields(raw json.RawMessage, keys []string) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != len(keys) || !canonicalFields(m, keys) {
		return nil, false
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, false
		}
	}
	return m, true
}
func strictExceptionFields(m map[string]json.RawMessage) bool {
	if raw, ok := m["maxExceptionDays"]; ok {
		var days int
		if json.Unmarshal(raw, &days) != nil || days <= 0 || days > MaxConfiguredExceptionDays {
			return false
		}
	}
	for k := range m {
		for _, want := range []string{"exceptions", "maxExceptionDays"} {
			if strings.EqualFold(k, want) && k != want {
				return false
			}
		}
	}
	raw, ok := m["exceptions"]
	if !ok {
		return true
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 64 {
		return false
	}
	for _, row := range rows {
		fields, ok := strictFields(row, []string{"id", "reason", "owner", "approvedAt", "expiresAt", "scope", "acceptance"})
		if !ok {
			return false
		}
		if _, ok = strictFields(fields["scope"], []string{"project", "category", "rule", "class", "package", "version", "origin", "instance", "path", "advisory", "change"}); !ok {
			return false
		}
	}
	return true
}
