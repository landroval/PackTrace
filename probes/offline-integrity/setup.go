// Package offlineintegrity holds the trusted, manual-only qualification probe.
// Default tests validate setup data only; they do not launch native cases.
package offlineintegrity

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	rowDeadline           = 15 * time.Minute
	childDeadline         = 10 * time.Second
	cleanupDeadline       = 2 * time.Second
	maxLaunches           = 100
	maxRaceIterations     = 50
	maxFixtureBytes       = 32 << 20
	maxEntries            = 1000
	maxTouchedBytes       = 64 << 20
	observedStopBytes     = 512 << 20 // sampled stop, NEVER a ceiling
	maxEvidenceBytes      = 32 << 20
	maxStderrBytes        = 64 << 10
	maxNewBuildCacheBytes = 2 << 30 // enforced/receipted by runner preparation, not Go
)

// Setup is a coordinator-supplied preparation receipt. Equality checks below do
// not authenticate a checkout, toolchain, installed SDK, OS image or filesystem.
// Independent preparation/review must bind those facts before dispatch.
type Setup struct {
	SourceSHA, ExpectedSHA, GoVersion, GoArtifactSHA256, BuildFlags string
	OS, Arch, OSVersion, Kernel, Filesystem, UID                    string
	SDK, SDKChecksum, Profile                                       string
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func (s Setup) validate() error {
	bad := errors.New("qualification: blocked-setup")
	if !validHex(s.SourceSHA, 40) || s.SourceSHA != s.ExpectedSHA || s.GoVersion != "go1.27.1" || !validHex(s.GoArtifactSHA256, 64) || s.BuildFlags != "-tags=nativequalification" || s.Profile != "owned-fixtures-v1" || s.Kernel == "" || s.Filesystem == "" || s.UID == "" {
		return bad
	}
	switch s.OS {
	case "darwin":
		if (s.Arch != "amd64" && s.Arch != "arm64") || !strings.HasPrefix(s.OSVersion, "15.") || s.SDK == "" || !validHex(s.SDKChecksum, 64) {
			return bad
		}
	case "linux":
		if (s.Arch != "amd64" && s.Arch != "arm64") || s.OSVersion != "Ubuntu 24.04" {
			return bad
		}
	case "windows":
		if s.Arch != "amd64" || s.OSVersion != "Windows Server 2022" {
			return bad
		}
	default:
		return bad
	}
	return nil
}
