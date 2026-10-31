package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

type Environment struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Go            string `json:"go"`
	CGO           string `json:"cgo"`
	OSVersion     string `json:"osVersion"`
	OSBuild       string `json:"osBuild"`
	Kernel        string `json:"kernel"`
	Filesystem    string `json:"filesystem"`
	Mount         string `json:"mount"`
	MountFlags    uint64 `json:"mountFlags"`
	CaseSensitive *bool  `json:"caseSensitive"`
	UID           int    `json:"uid"`
	API           string `json:"api"`
	Flags         int    `json:"flags"`
	Reason        string `json:"reason"`
}
type Sample struct {
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	CtimeSec  int64  `json:"ctimeSec"`
	CtimeNsec int64  `json:"ctimeNsec"`
	Nlink     uint64 `json:"nlink"`
	Mode      uint32 `json:"mode"`
	Size      int64  `json:"size"`
}
type Observation struct {
	Errno       uint32   `json:"errno"`
	Before      Sample   `json:"sourceBefore"`
	AtClone     Sample   `json:"sourceAtCloneSample"`
	After       Sample   `json:"sourceAfter"`
	Destination Sample   `json:"destination"`
	Bytes       int64    `json:"bytes"`
	Digest      [32]byte `json:"sha256Bytes"`
}
type Case struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"`
	Reason      string       `json:"reason"`
	Observation *Observation `json:"observation,omitempty"`
	DataEqual   bool         `json:"actualDataEqual"`
	Distinct    bool         `json:"distinctDestination"`
	COW         bool         `json:"cowIndependenceObserved"`
	NotBinding  bool         `json:"notOriginalBindingObserved"`
	APICOWClaim string       `json:"atomicCOWClaim"`
}
type Cleanup struct {
	Clean        bool     `json:"clean"`
	WorkerReaped bool     `json:"workerReaped"`
	Residue      []string `json:"residue"`
}
type Receipt struct {
	Schema        string      `json:"schema"`
	Scope         string      `json:"scope"`
	Qualification string      `json:"qualification"`
	Binding       string      `json:"sourceObjectBinding"`
	Status        string      `json:"status"`
	Cases         []Case      `json:"cases"`
	Environment   Environment `json:"environment"`
	Cleanup       Cleanup     `json:"cleanup"`
}

var caseIDs = []string{"regular", "cow", "direct-link", "selected-link", "swap"}

const literalA = "owned-literal-A\n"
const literalB = "owned-literal-B\n"

func profileOK(e Environment) bool {
	parts := strings.Split(e.OSVersion, ".")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "15" {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 16); err != nil {
			return false
		}
	}
	return e.OS == "darwin" && e.Arch == "arm64" && e.Go == "go1.27.1" && e.CGO == "0" && e.UID > 0 && e.OSBuild != "" && e.Kernel != ""
}

// Cumulative, including the supplied evidence root, both directories, originals,
// link, spare, and all possible destination creations (even a bad link clone).
func plan(entries int, bytes int64) bool {
	return entries >= 0 && entries <= 16 && bytes >= 0 && bytes <= 65536
}
func baseReceipt(e Environment) Receipt {
	r := Receipt{Schema: "packtrace.macos-clone-probe.v1", Scope: "controlled-fixture-feasibility", Qualification: "not-qualified", Binding: "not-established", Status: "BLOCKED", Environment: e, Cleanup: Cleanup{Clean: true, WorkerReaped: true, Residue: []string{}}}
	for _, id := range caseIDs {
		r.Cases = append(r.Cases, Case{ID: id, Status: "NOT RUN", Reason: "preflight"})
	}
	return r
}
func sameObject(a, b Sample) bool { return a.Device == b.Device && a.Inode == b.Inode }
func regular(s Sample) bool {
	return s.Mode&0170000 == 0100000 && s.Nlink == 1 && s.Size == int64(len(literalA))
}
func classify(id byte, o Observation) Case {
	c := Case{ID: "invalid", Status: "FAIL", Reason: "invalid-case", Observation: &o}
	if id < 1 || int(id) > len(caseIDs) {
		return c
	}
	c.ID = caseIDs[id-1]
	c.Reason = "observation-mismatch"
	// These are Darwin wire errno numbers from pinned x/sys, NOT host errno.
	if o.Errno == 45 || o.Errno == 18 || o.Errno == 78 || o.Errno == 22 {
		c.Status = "BLOCKED"
		c.Reason = "clone-capability-unavailable"
		return c
	}
	if id == 3 {
		if o.Errno == 62 && o.Destination.Inode == 0 {
			c.Status = "PASS"
			c.Reason = "no-follow-refused"
		}
		return c
	}
	if o.Errno != 0 {
		c.Reason = "clone-error"
		return c
	}
	c.APICOWClaim = "clonefileat-contract-only"
	want := sha256.Sum256([]byte(literalA))
	if id == 5 {
		want = sha256.Sum256([]byte(literalB))
	}
	c.DataEqual = o.Digest == want && o.Bytes == int64(len(literalA))
	c.Distinct = o.Destination.Device == o.AtClone.Device && !sameObject(o.Destination, o.AtClone) && !sameObject(o.Destination, o.Before)
	if !regular(o.Before) || !regular(o.AtClone) || !regular(o.After) || !regular(o.Destination) || !c.DataEqual || !c.Distinct {
		return c
	}
	if id == 5 {
		if sameObject(o.Before, o.AtClone) || !sameObject(o.Before, o.After) {
			return c
		}
		c.NotBinding = true
		c.Reason = "B-clone-with-restored-A-path-samples"
	} else {
		if !sameObject(o.Before, o.AtClone) || !sameObject(o.Before, o.After) {
			return c
		}
		c.Reason = "owned-clone-data-equal-distinct"
	}
	if id == 2 {
		c.COW = true
		c.Reason = "A-clone-after-trusted-B-overwrite"
	}
	if id == 4 {
		c.Reason = "known-link-selection-not-production-resolver"
	}
	c.Status = "PASS"
	return c
}
func finish(r *Receipt, fatal bool) int {
	if fatal || !r.Cleanup.Clean || !r.Cleanup.WorkerReaped {
		r.Status = "FAIL"
		return 2
	}
	r.Status = "PASS"
	code := 0
	for _, c := range r.Cases {
		if c.Status == "FAIL" {
			r.Status = "FAIL"
			return 1
		}
		if c.Status != "PASS" {
			r.Status = "BLOCKED"
			code = 3
		}
	}
	return code
}
func validReceipt(r Receipt, code int) bool {
	if r.Schema != "packtrace.macos-clone-probe.v1" || r.Scope != "controlled-fixture-feasibility" || r.Qualification != "not-qualified" || r.Binding != "not-established" || len(r.Cases) != 5 {
		return false
	}
	if r.Environment.API != "clonefileat" || r.Environment.Flags != 10 || (r.Cleanup.Clean && (!r.Cleanup.WorkerReaped || len(r.Cleanup.Residue) != 0)) {
		return false
	}
	for i, c := range r.Cases {
		if c.ID != caseIDs[i] {
			return false
		}
		if c.Observation == nil {
			if c != (Case{ID: caseIDs[i], Status: "NOT RUN", Reason: "preflight"}) {
				return false
			}
			continue
		}
		e := r.Environment
		if !profileOK(e) || e.Filesystem != "apfs" || e.Mount == "" || e.MountFlags&4096 == 0 || e.MountFlags&1 != 0 || (e.Reason != "controlled-cases-observed" && e.Reason != "observer-protocol-or-supervision-failed") {
			return false
		}
		expected := classify(byte(i+1), *c.Observation)
		expected.Observation = c.Observation
		if c != expected {
			return false
		}
	}
	fatal := false
	switch r.Environment.Reason {
	case "invalid-arguments", "budget-rejected", "invalid-evidence-directory", "fixture-setup-failed", "self-executable-unavailable", "capability-unavailable", "capability-pipe-failed", "capability-write-failed", "observer-protocol-or-supervision-failed":
		fatal = true
	case "", "unsupported-profile", "nonplain-evidence-directory", "filesystem-unavailable", "unsupported-filesystem", "controlled-cases-observed":
	default:
		return false
	}
	for _, residue := range r.Cleanup.Residue {
		switch residue {
		case "unreaped-worker", "stage-C", "fixture-artifact", "unknown-fixture-residue", "unknown-stage-residue", "owned-directory", "unknown-root-residue":
		default:
			return false
		}
	}
	v := r
	want := finish(&v, fatal)
	return want == code && v.Status == r.Status
}
func emit(w io.Writer, r Receipt) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b)+1 > 16384 {
		return errors.New("receipt-budget")
	}
	b = append(b, '\n')
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
