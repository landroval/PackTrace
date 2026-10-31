package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// Removing any one guard must admit its bad profile and fail this test.
func TestProfile(t *testing.T) {
	good := Environment{OS: "darwin", Arch: "arm64", Go: "go1.27.1", CGO: "0", OSVersion: "15.7.1", OSBuild: "24G90", Kernel: "24.6.0", UID: 501}
	if !profileOK(good) {
		t.Fatal("selected profile rejected")
	}
	variants := []Environment{good, good, good, good, good, good, good, good, good, good}
	variants[0].OS = "linux"
	variants[1].Arch = "amd64"
	variants[2].Go = "go1.27.3"
	variants[3].CGO = "1"
	variants[4].OSVersion = "150.1"
	variants[5].OSVersion = "16.0"
	variants[6].OSVersion = "15.bad"
	variants[7].UID = 0
	variants[8].OSBuild = ""
	variants[9].Kernel = ""
	for i, e := range variants {
		if profileOK(e) {
			t.Errorf("bad profile %d admitted", i)
		}
	}
}
func TestCumulativePlan(t *testing.T) {
	for _, v := range []struct {
		n    int
		b    int64
		want bool
	}{{11, 512, true}, {16, 65536, true}, {17, 1, false}, {1, 65537, false}, {-1, 1, false}, {1, -1, false}} {
		if plan(v.n, v.b) != v.want {
			t.Errorf("plan(%d,%d)", v.n, v.b)
		}
	}
}
func regularObservation() Observation {
	return Observation{Before: Sample{Device: 1, Inode: 10, Mode: 0100600, Nlink: 1, Size: 16}, AtClone: Sample{Device: 1, Inode: 10, Mode: 0100600, Nlink: 1, Size: 16}, After: Sample{Device: 1, Inode: 10, Mode: 0100600, Nlink: 1, Size: 16}, Destination: Sample{Device: 1, Inode: 11, Mode: 0100600, Nlink: 1, Size: 16}, Bytes: 16, Digest: sha256.Sum256([]byte("owned-literal-A\n"))}
}
func TestClassification(t *testing.T) {
	a := regularObservation()
	if c := classify(1, a); c.Status != "PASS" || !c.DataEqual || !c.Distinct {
		t.Fatalf("positive: %+v", c)
	}
	cow := a
	cow.After.Size = 16
	if c := classify(2, cow); c.Status != "PASS" || !c.COW {
		t.Fatalf("cow: %+v", c)
	}
	swap := a
	swap.AtClone.Inode = 12
	swap.Digest = sha256.Sum256([]byte("owned-literal-B\n"))
	if c := classify(5, swap); c.Status != "PASS" || !c.NotBinding {
		t.Fatalf("swap: %+v", c)
	}
	for _, id := range []byte{1, 2, 4, 5} {
		b := a
		b.Digest = [32]byte{}
		if classify(id, b).Status != "FAIL" {
			t.Errorf("bad data %d admitted", id)
		}
		b = a
		b.Destination.Inode = 10
		if classify(id, b).Status != "FAIL" {
			t.Errorf("same inode %d admitted", id)
		}
		b = a
		b.Destination.Mode = 0040700
		if classify(id, b).Status != "FAIL" {
			t.Errorf("directory %d admitted", id)
		}
		b = a
		b.Errno = 45
		if classify(id, b).Status != "BLOCKED" {
			t.Errorf("unsupported %d passed", id)
		}
		b = a
		b.Errno = 13
		if classify(id, b).Status != "FAIL" {
			t.Errorf("unexpected error %d passed", id)
		}
	}
	for _, errno := range []uint32{62} {
		o := Observation{Errno: errno}
		if classify(3, o).Status != "PASS" {
			t.Errorf("no-follow refusal %d", errno)
		}
	}
	if classify(3, a).Status != "FAIL" {
		t.Fatal("successful direct-link clone accepted")
	}
	if classify(3, Observation{Errno: 22}).Status != "BLOCKED" {
		t.Fatal("EINVAL does not attest no-follow")
	}
	if classify(3, Observation{Errno: 40}).Status == "PASS" {
		t.Fatal("Linux errno used on Darwin wire")
	}
	if classify(3, Observation{Errno: 45}).Status != "BLOCKED" {
		t.Fatal("unsupported no-follow not blocked")
	}
	if classify(0, a).Status != "FAIL" {
		t.Fatal("invalid case accepted")
	}
	swap.After.Inode = 12
	if classify(5, swap).Status != "FAIL" {
		t.Fatal("swap without restored A accepted")
	}
}

// Complete controlled observations, never native API evidence.
func completeReceipt() Receipt {
	e := Environment{OS: "darwin", Arch: "arm64", Go: "go1.27.1", CGO: "0", OSVersion: "15.7.1", OSBuild: "24G90", Kernel: "24.6.0", UID: 501, API: "clonefileat", Flags: 10, Filesystem: "apfs", Mount: "/owned", MountFlags: 4096, Reason: "controlled-cases-observed"}
	r := baseReceipt(e)
	for i := range r.Cases {
		o := regularObservation()
		if i == 2 {
			o = Observation{Errno: 62}
		}
		if i == 4 {
			o.AtClone.Inode = 12
			o.Digest = sha256.Sum256([]byte("owned-literal-B\n"))
		}
		r.Cases[i] = classify(byte(i+1), o)
	}
	finish(&r, false)
	return r
}

func TestReceiptObservationContract(t *testing.T) {
	good := completeReceipt()
	if !validReceipt(good, 0) {
		t.Fatal("complete controlled receipt rejected")
	}
	for _, change := range []func(*Receipt){
		func(r *Receipt) { r.Environment.OS = "linux" },
		func(r *Receipt) { r.Environment.Filesystem = "other" },
		func(r *Receipt) { r.Cases[0].Observation = nil },
		func(r *Receipt) { r.Cases[0].Observation.Digest = [32]byte{} },
		func(r *Receipt) { r.Cases[1].COW = false },
		func(r *Receipt) { r.Cases[4].NotBinding = false },
		func(r *Receipt) { r.Cases[2].Observation.Errno = 40 },
		func(r *Receipt) { r.Cases[0].APICOWClaim = "atomic" },
		func(r *Receipt) { r.Cleanup.Residue = []string{"unknown-root-residue"} },
	} {
		r := completeReceipt()
		change(&r)
		if validReceipt(r, 0) {
			t.Fatalf("inconsistent receipt admitted: %+v", r)
		}
	}
	fatal := baseReceipt(Environment{API: "clonefileat", Flags: 10, Reason: "invalid-arguments"})
	fatal.Status = "FAIL"
	if !validReceipt(fatal, 2) {
		t.Fatal("valid fatal exit 2 rejected")
	}
}

func TestReceiptAggregationAndValidation(t *testing.T) {
	r := baseReceipt(Environment{})
	if code := finish(&r, false); code != 3 || r.Status != "BLOCKED" {
		t.Fatalf("unrun receipt: %d %+v", code, r)
	}
	r = completeReceipt()
	if code := finish(&r, false); code != 0 || !validReceipt(r, code) {
		t.Fatalf("positive receipt: %d %+v", code, r)
	}
	var out bytes.Buffer
	if err := emit(&out, r); err != nil {
		t.Fatal(err)
	}
	if out.Len() > 65536 || out.Bytes()[out.Len()-1] != '\n' || bytes.Count(out.Bytes(), []byte("\n")) != 1 {
		t.Fatal("not one bounded JSON line")
	}
	var parsed Receipt
	if json.Unmarshal(out.Bytes(), &parsed) != nil {
		t.Fatal("invalid JSON")
	}
	for _, mutate := range []func(*Receipt){func(r *Receipt) { r.Qualification = "qualified" }, func(r *Receipt) { r.Binding = "established" }, func(r *Receipt) { r.Schema = "other" }, func(r *Receipt) { r.Scope = "production" }, func(r *Receipt) { r.Cases[0].ID = "forged" }, func(r *Receipt) { r.Cleanup.Clean = false }, func(r *Receipt) { r.Cleanup.WorkerReaped = false }, func(r *Receipt) { r.Status = "FAKE" }} {
		v := r
		v.Cases = append([]Case(nil), r.Cases...)
		mutate(&v)
		if validReceipt(v, 0) {
			t.Fatal("forged receipt admitted")
		}
	}
	r.Cases[1].Status = "BLOCKED"
	if finish(&r, false) != 3 {
		t.Fatal("blocked relabeled")
	}
	r.Cases[2].Status = "FAIL"
	if finish(&r, false) != 1 {
		t.Fatal("fail relabeled")
	}
	r.Cleanup.Clean = false
	if finish(&r, false) != 2 {
		t.Fatal("residue accepted")
	}
	r.Cleanup.Clean = true
	if finish(&r, true) != 2 {
		t.Fatal("fatal accepted")
	}
	r.Cases[0].Reason = string(bytes.Repeat([]byte("x"), 65536))
	out.Reset()
	if emit(&out, r) == nil || out.Len() != 0 {
		t.Fatal("oversized receipt written")
	}
}
