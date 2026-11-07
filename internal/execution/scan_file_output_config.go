package execution

import (
	"path/filepath"
	"strings"
)

type writerLaunchConfig struct {
	Nonce  string                `json:"nonce"`
	Size   int                   `json:"size"`
	SHA256 string                `json:"sha256"`
	File   *scanFileOutputConfig `json:"file,omitempty"`
}

// Private fixed-role DTO. Paths select independently admitted native originals;
// Binding is continuity, never authority or a substitute for the generation pin.
type scanFileOutputConfig struct {
	Target          string                  `json:"target"`
	PolicyDirectory string                  `json:"policyDirectory,omitempty"`
	Destination     string                  `json:"destination"`
	Binding         string                  `json:"binding"`
	Intelligence    *scanIntelligenceConfig `json:"intelligence,omitempty"`
}

func (c *scanFileOutputConfig) valid() bool {
	if c == nil || !filepath.IsAbs(c.Target) || !filepath.IsAbs(c.Destination) || !strings.HasPrefix(c.Binding, "sha256-") || !intelResultID(strings.TrimPrefix(c.Binding, "sha256-")) || (c.PolicyDirectory != "" && !filepath.IsAbs(c.PolicyDirectory)) {
		return false
	}
	if v := c.Intelligence; v != nil {
		if !filepath.IsAbs(v.Path) || !intelResultID(v.TargetBinding) || v.NowUnixNS <= 0 {
			return false
		}
		if v.Generation == "" {
			return v.Binding == "" && v.Selection == "none"
		}
		return intelResultID(v.Generation) && intelResultID(v.Binding) && one(v.Selection, "current", "previous-fallback", "expected-digest")
	}
	return true
}
