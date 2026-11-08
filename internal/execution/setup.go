package execution

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/jsoninput"
	"packtrace/internal/nativefs"
)

const userSetupName = "setup.json"
const maxUserSetupBytes = 4096

var ErrUserSetup = errors.New("scan: user-setup-invalid; run packtrace setup --help")
var ErrSetupPolicy = errors.New("setup: select a policy once with packtrace setup --policy FILE [--state-dir DIR]")
var ErrSetupWrite = errors.New("setup: configuration unavailable or already exists; existing configuration was not replaced")

// This is operator configuration, not target evidence or publisher authentication.
// Policy approval is captured only by explicit setup, never recomputed by scan.
type userSetup struct {
	Version               int                `json:"version"`
	Root                  string             `json:"root"`
	PolicyPath            string             `json:"policyPath"`
	PolicyDigest          string             `json:"policyDigest"`
	StateDir              string             `json:"stateDir"`
	TrustedSnapshotDigest string             `json:"trustedSnapshotDigest"`
	Privacy               string             `json:"privacy"`
	Checks                cli.ArgumentChecks `json:"checks"`
}

func userSetupDirectory() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(base) {
		return "", ErrUserSetup
	}
	return filepath.Join(base, "packtrace"), nil
}

func parseUserSetup(data []byte) (userSetup, error) {
	fields, code := jsoninput.Object(data, maxUserSetupBytes)
	if code != "" || len(fields) != 8 {
		return userSetup{}, ErrUserSetup
	}
	for _, name := range []string{"version", "root", "policyPath", "policyDigest", "stateDir", "trustedSnapshotDigest", "privacy", "checks"} {
		if raw, ok := fields[name]; !ok || string(raw) == "null" {
			return userSetup{}, ErrUserSetup
		}
	}
	var s userSetup
	if json.Unmarshal(data, &s) != nil || s.Version != 1 || !filepath.IsAbs(s.PolicyPath) || filepath.Clean(s.PolicyPath) != s.PolicyPath || !filepath.IsAbs(s.StateDir) || filepath.Clean(s.StateDir) != s.StateDir || s.Privacy != "local" && s.Privacy != "portable" || s.Checks == 0 || s.Checks & ^cli.ArgumentChecks(7) != 0 {
		return s, ErrUserSetup
	}
	id, err := hex.DecodeString(s.Root)
	if err != nil || len(id) != 32 || hex.EncodeToString(id) != s.Root || [32]byte(id) == ([32]byte{}) {
		return s, ErrUserSetup
	}
	pin, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(s.PolicyDigest, "sha256-"))
	if err != nil || len(pin) != 32 || "sha256-"+base64.StdEncoding.EncodeToString(pin) != s.PolicyDigest {
		return s, ErrUserSetup
	}
	if s.TrustedSnapshotDigest != "" {
		if _, err := cli.ParseArgs([]string{"scan", "--trusted-snapshot-digest", s.TrustedSnapshotDigest, "unused"}); err != nil {
			return s, ErrUserSetup
		}
	}
	return s, nil
}

func setupPolicy(ctx context.Context, path string) (data []byte, failure error) {
	r, err := nativefs.OpenRoot(ctx, filepath.Dir(path))
	if err != nil {
		return nil, ErrSetupPolicy
	}
	defer func() { failure = errors.Join(failure, r.Close()) }()
	f, err := r.OpenInput(ctx, filepath.Base(path), integrityscan.MaxPolicyBytes)
	if err != nil {
		return nil, ErrSetupPolicy
	}
	defer func() { failure = errors.Join(failure, f.Close()) }()
	data, err = io.ReadAll(f)
	if err != nil || f.Stable() != nil {
		return nil, ErrSetupPolicy
	}
	return data, nil
}

// RunSetup writes only explicit application configuration. It neither scans a
// target nor initializes, reads, downloads or renews an intelligence generation.
func RunSetup(ctx context.Context, request cli.SetupArgumentRequest) (failure error) {
	if request.PolicyPath == "" {
		return ErrSetupPolicy
	}
	policy, err := filepath.Abs(request.PolicyPath)
	if err != nil {
		return ErrSetupPolicy
	}
	data, err := setupPolicy(ctx, policy)
	if err != nil {
		return ErrSetupPolicy
	}
	p, err := integrityscan.ParsePolicy(data)
	if err != nil {
		return ErrSetupPolicy
	}
	state := request.StateDir
	if state == "" {
		state, err = defaultIntelStateDirectory()
	} else {
		state, err = filepath.Abs(state)
	}
	if err != nil {
		return ErrUserSetup
	}
	privacy := request.Privacy
	if privacy == "" {
		privacy = "local"
	}
	parsed, err := cli.ParseArgs([]string{"scan", "--checks", strings.Join(p.RequiredChecks, ","), "unused"})
	if err != nil {
		return ErrSetupPolicy
	}
	sum := sha256.Sum256(data)
	s := userSetup{Version: 1, PolicyPath: policy, PolicyDigest: "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), StateDir: state, TrustedSnapshotDigest: request.TrustedSnapshotDigest, Privacy: privacy, Checks: parsed.Scan.Checks}
	// Exercise the existing policy precedence/portable/pin validators before writing.
	r := parsed.Scan
	r.Manager, r.PolicyPath, r.TrustedPolicyDigest, r.StateDir, r.Privacy, r.TrustedSnapshotDigest = "auto", policy, s.PolicyDigest, state, privacy, s.TrustedSnapshotDigest
	if _, err := integrityscan.Configure(r, p); err != nil {
		return ErrSetupPolicy
	}
	dir, err := userSetupDirectory()
	if err != nil {
		return err
	}
	// Create a missing standard config base without recursive mkdir/symlink traversal.
	if _, err := os.Lstat(filepath.Dir(dir)); errors.Is(err, os.ErrNotExist) {
		base, err := nativefs.OpenOwnedDirectory(ctx, filepath.Dir(dir), true)
		if err != nil {
			return ErrSetupWrite
		}
		if err := base.Close(); err != nil {
			return ErrSetupWrite
		}
	}
	owner, err := nativefs.OpenOwnedDirectory(ctx, dir, true)
	if err != nil {
		owner, err = nativefs.OpenOwnedDirectory(ctx, dir, false)
	}
	if err != nil {
		return ErrSetupWrite
	}
	defer func() { failure = errors.Join(failure, owner.Close()) }()
	id, err := owner.ReadRoot().OwnedIdentity(ctx)
	if err != nil {
		return ErrSetupWrite
	}
	s.Root = hex.EncodeToString(id[:])
	encoded, err := json.Marshal(s)
	if err != nil {
		return ErrSetupWrite
	}
	if _, err := parseUserSetup(encoded); err != nil {
		return err
	}
	// ponytail: one active policy, exclusive first setup; named profiles/atomic
	// replacement can follow when reconfiguration is needed. Never clobber.
	if err := owner.WriteControl(ctx, userSetupName, encoded); err != nil {
		return ErrSetupWrite
	}
	return nil
}

type scanSetupOwner struct {
	target, root *nativefs.Root
	file         *nativefs.File
	identity     [32]byte
	closed       bool
}

// Only the OS user-config location is consulted, never cwd or the target.
// Physical separation and ownership are proven before a configuration byte is read.
func loadScanSetup(ctx context.Context, targetPath string, request cli.ScanArgumentRequest) (owner *scanSetupOwner, result cli.ScanArgumentRequest, failure error) {
	result = request
	if request.PolicyPath != "" || request.TrustedPolicyDigest != "" {
		return nil, result, nil // An explicit policy is a complete selection, not a merge.
	}
	dir, err := userSetupDirectory()
	if err != nil {
		return nil, result, err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, result, nil
	} else if err != nil {
		return nil, result, ErrUserSetup
	}
	o := &scanSetupOwner{}
	owner = o // Retain even partial admission through confirmed reap.
	o.target, err = nativefs.OpenRoot(ctx, targetPath)
	if err != nil {
		return o, result, ErrUserSetup
	}
	o.root, err = o.target.OpenExternalRoot(ctx, dir)
	if err != nil {
		return o, result, ErrUserSetup
	}
	o.identity, err = o.root.OwnedIdentity(ctx)
	if err != nil {
		return o, result, ErrUserSetup
	}
	o.file, err = o.root.OpenInput(ctx, userSetupName, maxUserSetupBytes)
	if err != nil {
		return o, result, ErrUserSetup
	}
	data, err := io.ReadAll(o.file)
	if err != nil || o.file.Stable() != nil {
		return o, result, ErrUserSetup
	}
	s, err := parseUserSetup(data)
	if err != nil || s.Root != hex.EncodeToString(o.identity[:]) {
		return o, result, ErrUserSetup
	}
	result.PolicyPath, result.TrustedPolicyDigest = s.PolicyPath, s.PolicyDigest
	if request.Provided&cli.ArgumentOptionStateDir == 0 && request.StateDir == "" {
		result.StateDir = s.StateDir
	}
	if request.Provided&cli.ArgumentOptionTrustedSnapshotDigest == 0 && request.TrustedSnapshotDigest == "" {
		result.TrustedSnapshotDigest = s.TrustedSnapshotDigest
	}
	if request.Provided&cli.ArgumentOptionPrivacy == 0 {
		result.Privacy = s.Privacy
	}
	if request.Provided&cli.ArgumentOptionChecks == 0 {
		result.Checks = s.Checks
	}
	return o, result, o.check(ctx)
}

func (o *scanSetupOwner) check(ctx context.Context) error {
	if o == nil || o.closed || o.file == nil || o.root == nil || o.file.Stable() != nil {
		return ErrUserSetup
	}
	id, err := o.root.OwnedIdentity(ctx)
	if err != nil || id != o.identity {
		return ErrUserSetup
	}
	return nil
}
func (o *scanSetupOwner) close() error {
	if o == nil || o.closed {
		return nil
	}
	o.closed = true
	var err error
	if o.file != nil {
		err = errors.Join(err, o.file.Close())
	}
	if o.root != nil {
		err = errors.Join(err, o.root.Close())
	}
	if o.target != nil {
		err = errors.Join(err, o.target.Close())
	}
	return err
}
