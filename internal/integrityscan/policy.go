// Package integrityscan connects explicit offline policy, native observations and
// the integrity engine. Its candidate results never assert native qualification.
package integrityscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"packtrace/internal/cli"
	"packtrace/internal/jsoninput"
)

const MaxPolicyBytes = 256 << 10

var ErrPolicy = errors.New("scan: invalid-policy")
var ErrOptions = errors.New("scan: unsupported-or-conflicting-options")

// Policy is selected explicitly by the operator, never discovered in the target.
// Its text assertions are provenance, not proof of physical independence.
type Policy struct {
	Version                int         `json:"version"`
	Designation            string      `json:"designation"`
	Reason                 string      `json:"reason"`
	Provenance             string      `json:"provenance"`
	Manager                string      `json:"manager"`
	RequiredChecks         []string    `json:"requiredChecks"`
	FailOn                 []string    `json:"failOn"`
	RequireHardMemoryLimit bool        `json:"requireHardMemoryLimit"`
	MinimumAssurance       string      `json:"minimumAssurance"`
	References             []Reference `json:"references"`
}
type Reference struct {
	Location       string `json:"location"`
	LockKey        string `json:"lockKey"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	Origin         string `json:"origin"`
	Classification string `json:"classification"`
	ExpectedSRI    string `json:"expectedSRI"`
	Archive        string `json:"archive"`
	Context        string `json:"context"`
}
type Plan struct {
	// PolicyFile is a source selector, never authority. Acquisition must reread
	// it through a newly proven external capability before target content.
	PolicyFile          string             `json:"policyFile"`
	TrustedPolicyDigest string             `json:"trustedPolicyDigest,omitempty"`
	Manager             string             `json:"manager"`
	Checks              cli.ArgumentChecks `json:"checks"`
	FailOn              cli.ArgumentChecks `json:"failOn"`
	Policy              Policy             `json:"policy"`
}

func ParsePolicy(data []byte) (Policy, error) {
	if _, code := jsoninput.Object(data, MaxPolicyBytes); code != "" {
		return Policy{}, ErrPolicy
	}
	var p Policy
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || ValidatePolicy(p) != nil {
		return Policy{}, ErrPolicy
	}
	return p, nil
}
func ValidatePolicy(p Policy) error {
	if p.Version != 1 || p.Designation != "user-designated" || !text(p.Reason, 4096) || !text(p.Provenance, 4096) || !profile(p.Manager) || p.RequireHardMemoryLimit || (p.MinimumAssurance != "lockfile-consistent" && p.MinimumAssurance != "independently-anchored") || len(p.References) > 20000 || p.References == nil {
		return ErrPolicy
	}
	checks, ok := categories(p.RequiredChecks)
	if !ok || checks == 0 {
		return ErrPolicy
	}
	fail, ok := categories(p.FailOn)
	if !ok || fail & ^checks != 0 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, r := range p.References {
		key := strings.ToLower(r.Location)
		if !relative(r.Location) || !relative(r.LockKey) || !relative(r.Archive) || seen[key] || !text(r.Name, 214) || !text(r.Version, 256) || !text(r.Origin, 2048) || !oneOf(r.Classification, "public", "private", "unknown") || !oneOf(r.Context, "none", "patch", "generated") || !strongSRI(r.ExpectedSRI) {
			return ErrPolicy
		}
		seen[key] = true
	}
	return nil
}
func Configure(r cli.ScanArgumentRequest, p Policy) (Plan, error) {
	if ValidatePolicy(p) != nil {
		return Plan{}, ErrPolicy
	}
	required, _ := categories(p.RequiredChecks)
	fail, _ := categories(p.FailOn)
	if r.PolicyPath == "" || r.Privacy != "portable" || r.Output != "-" || r.StateDir != "" || (p.MinimumAssurance == "independently-anchored" && r.TrustedPolicyDigest == "") || (r.TrustedPolicyDigest != "" && !supportedPolicyPin(r.TrustedPolicyDigest)) || required & ^r.Checks != 0 || (r.FailOn|fail) & ^r.Checks != 0 {
		return Plan{}, ErrOptions
	}
	family := strings.Split(p.Manager, "@")[0]
	if r.Manager != "auto" && r.Manager != family && r.Manager != p.Manager {
		return Plan{}, ErrOptions
	}
	return Plan{PolicyFile: filepath.Base(r.PolicyPath), TrustedPolicyDigest: r.TrustedPolicyDigest, Manager: p.Manager, Checks: r.Checks, FailOn: r.FailOn | fail, Policy: p}, nil
}
func categories(values []string) (cli.ArgumentChecks, bool) {
	if values == nil {
		return 0, false
	}
	var result cli.ArgumentChecks
	for _, v := range values {
		var bit cli.ArgumentChecks
		switch v {
		case "integrity":
			bit = cli.ArgumentCheckIntegrity
		case "malicious":
			bit = cli.ArgumentCheckMalicious
		case "vulnerability":
			bit = cli.ArgumentCheckVulnerability
		default:
			return 0, false
		}
		if result&bit != 0 {
			return 0, false
		}
		result |= bit
	}
	return result, true
}
func profile(s string) bool {
	return oneOf(s, "npm@8.19.4", "npm@10.9.4", "npm@11.6.2", "bun@1.3.2", "bun@1.4.2")
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func text(s string, n int) bool {
	if len(s) == 0 || len(s) > n || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func relative(s string) bool {
	if !text(s, 4096) || path.Clean(s) != s || strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\:\x00<>\"|?*") || len(strings.Split(s, "/")) > 64 {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}
func strongSRI(s string) bool {
	tokens := strings.Fields(s)
	if len(tokens) == 0 || len(tokens) > 16 || len(s) > 2048 {
		return false
	}
	for _, token := range tokens {
		name, value, ok := strings.Cut(token, "-")
		if !ok {
			return false
		}
		n := 0
		switch name {
		case "sha256":
			n = 32
		case "sha384":
			n = 48
		case "sha512":
			n = 64
		default:
			return false
		}
		d, e := base64.StdEncoding.Strict().DecodeString(value)
		if e != nil || len(d) != n || base64.StdEncoding.EncodeToString(d) != value {
			return false
		}
	}
	return true
}
func sourceSRI(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// Limit every reader before allocating; the native lease independently enforces
// its actual-read/sentinel budget and Stable check.
func readBounded(r io.Reader, n int64) ([]byte, error) {
	data, e := io.ReadAll(io.LimitReader(r, n+1))
	if e != nil || int64(len(data)) > n {
		return nil, errors.New("scan: input-unusable")
	}
	return data, nil
}
