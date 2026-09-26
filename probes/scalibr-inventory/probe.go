// Package inventoryprobe is isolated evaluation code, not PackTrace implementation.
package inventoryprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"testing/fstest"
	"time"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/inventory"
)

const Module = "github.com/google/osv-scalibr@v0.5.3"
const MaxInputBytes = 2 * 1024 * 1024

type Case struct {
	ID                  string            `json:"id"`
	Group               string            `json:"group"`
	Extractor           string            `json:"extractor"`
	Path                string            `json:"path"`
	Content             string            `json:"content"`
	Files               map[string]string `json:"files,omitempty"`
	Enumerate           []string          `json:"enumerate,omitempty"`
	OpenDenied          bool              `json:"open_denied,omitempty"`
	StatDenied          bool              `json:"stat_denied,omitempty"`
	ReadError           bool              `json:"read_error,omitempty"`
	Canceled            bool              `json:"canceled,omitempty"`
	IncludeDependencies bool              `json:"include_dependencies,omitempty"`
	Oversize            bool              `json:"oversize,omitempty"`
	ReportedSize        int64             `json:"reported_size,omitempty"`
	Native              string            `json:"native,omitempty"`
	Gaps                []string          `json:"gaps"`
	Expect              Expectation       `json:"expect"`
}

type Expectation struct {
	Outcome  string   `json:"outcome"`
	Count    *int     `json:"count,omitempty"`
	Selected *bool    `json:"selected,omitempty"`
	Names    []string `json:"names,omitempty"`
}

type Package struct {
	Name       string                          `json:"name"`
	Version    string                          `json:"version"`
	Path       string                          `json:"path"`
	Line       int                             `json:"line"`
	ID         string                          `json:"id,omitempty"`
	Parents    map[string]bool                 `json:"parents,omitempty"`
	SourceCode *extractor.SourceCodeIdentifier `json:"source_code,omitempty"`
	Metadata   json.RawMessage                 `json:"metadata,omitempty"`
}

type Observation struct {
	CaseID        string            `json:"case_id"`
	Module        string            `json:"module"`
	InputSHA256   string            `json:"input_sha256"`
	EvidenceClass string            `json:"evidence_class"`
	Selected      bool              `json:"selected"`
	Error         string            `json:"error,omitempty"`
	Diagnostics   []string          `json:"diagnostics,omitempty"`
	Packages      []Package         `json:"packages"`
	Children      []Observation     `json:"children,omitempty"`
	Links         map[string]string `json:"links,omitempty"`
}

func Base(c Case) Observation {
	return Observation{CaseID: c.ID, Module: Module,
		InputSHA256:   fmt.Sprintf("%x", sha256.Sum256([]byte(c.Content))),
		EvidenceClass: "extractor-output-not-installation-proof", Packages: []Package{}}
}

func ReadCase() Case {
	if len(os.Args) != 2 {
		panic("expected one authored case ID")
	}
	data, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		panic(err)
	}
	var cases []Case
	if err := json.Unmarshal(data, &cases); err != nil {
		panic(err)
	}
	for _, c := range cases {
		if c.ID == os.Args[1] {
			return c
		}
	}
	panic("unknown authored case ID")
}

func Print(o Observation) {
	if err := json.NewEncoder(os.Stdout).Encode(o); err != nil {
		panic(err)
	}
}

func Normalize(inv inventory.Inventory) []Package {
	out := make([]Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		meta, err := json.Marshal(p.Metadata)
		if err != nil {
			panic(err) // Probe evidence encoding failure, never scanner success.
		}
		line := 0
		if p.Location.Descriptor != nil && p.Location.Descriptor.File != nil {
			line = p.Location.Descriptor.File.LineNumber
		}
		out = append(out, Package{Name: p.Name, Version: p.Version,
			Path: p.Location.PathOrEmpty(), Line: line, ID: p.ID, Parents: p.ParentIDs,
			SourceCode: p.SourceCode, Metadata: meta})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Path+"\x00"+a.Name+"\x00"+a.Version < b.Path+"\x00"+b.Name+"\x00"+b.Version
	})
	return out
}

// Observe intentionally does not recover upstream panics: the isolated child exits
// and the outer runner records the crash. No production parser is implemented here.
func Observe(c Case) Observation {
	if c.Native == "links" {
		return observeLinks(c)
	}
	if c.Native == "installed" || c.Native == "permission" {
		return observeInstalled(c)
	}
	if c.Native == "changing" {
		return observeChanging(c)
	}
	o, _ := Extract(c)
	return o
}

func Extract(c Case) (Observation, inventory.Inventory) {
	o := Base(c)
	if c.Oversize || len(c.Content) > MaxInputBytes {
		o.Error = "probe input exceeds 2 MiB"
		return o, inventory.Inventory{}
	}
	cfg := &cpb.PluginConfig{MaxFileSizeBytes: MaxInputBytes}
	cfg.PluginSpecific = []*cpb.PluginSpecificConfig{{Config: &cpb.PluginSpecificConfig_JavascriptPackageJson{
		JavascriptPackageJson: &cpb.JavascriptPackageJsonConfig{IncludeDependencies: c.IncludeDependencies},
	}}}
	var ex filesystem.Extractor
	var err error
	switch c.Extractor {
	case "npm":
		ex, err = packagelockjson.New(cfg)
	case "bun":
		ex, err = bunlock.New(cfg)
	case "manifest":
		ex, err = packagejson.New(cfg)
	default:
		o.Error = "unknown extractor"
		return o, inventory.Inventory{}
	}
	if err != nil {
		o.Error = err.Error()
		return o, inventory.Inventory{}
	}
	files := fstest.MapFS{}
	for name, content := range c.Files {
		files[name] = &fstest.MapFile{Data: []byte(content), Mode: 0444}
	}
	files[c.Path] = &fstest.MapFile{Data: []byte(c.Content), Mode: 0444}
	info, err := files.Stat(c.Path)
	if err != nil {
		o.Error = err.Error()
		return o, inventory.Inventory{}
	}
	if c.ReportedSize != 0 {
		info = sizedInfo{FileInfo: info, size: c.ReportedSize}
	}
	o.Selected = ex.FileRequired(fileAPI{path: c.Path, info: info, denied: c.StatDenied})
	if !o.Selected {
		o.Diagnostics = append(o.Diagnostics, "FileRequired=false; direct Extract still exercised deliberately")
	}
	if c.StatDenied {
		o.Diagnostics = append(o.Diagnostics, "injected Stat permission failure")
	}
	if c.OpenDenied {
		o.Diagnostics = append(o.Diagnostics, "injected sibling shrinkwrap Open permission failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if c.Canceled {
		cancel()
		o.Diagnostics = append(o.Diagnostics, "context canceled before Extract")
	}
	var reader io.Reader = strings.NewReader(c.Content)
	if c.ReadError {
		reader = io.MultiReader(strings.NewReader(c.Content[:len(c.Content)/2]), errorReader{})
	}
	inv, err := ex.Extract(ctx, &filesystem.ScanInput{FS: fixtureFS{base: files, denyShrinkwrap: c.OpenDenied},
		Path: c.Path, Root: "", Info: info, Reader: reader})
	o.Packages = Normalize(inv)
	if err != nil {
		o.Error = err.Error()
	}
	return o, inv
}

type sizedInfo struct {
	fs.FileInfo
	size int64
}

func (i sizedInfo) Size() int64 { return i.size }

type fileAPI struct {
	path   string
	info   fs.FileInfo
	denied bool
}

func (f fileAPI) Path() string { return f.path }
func (f fileAPI) Stat() (fs.FileInfo, error) {
	if f.denied {
		return nil, fs.ErrPermission
	}
	return f.info, nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("injected read failure") }

// The in-memory FS implements SCALIBR's documented ReaderAt contract as well.
type fixtureFS struct {
	base           fs.FS
	denyShrinkwrap bool
}

func (f fixtureFS) Open(name string) (fs.File, error) {
	if f.denyShrinkwrap && path.Base(name) == "npm-shrinkwrap.json" {
		return nil, fs.ErrPermission
	}
	info, err := fs.Stat(f.base, name)
	if err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(f.base, name)
	if err != nil {
		return nil, err
	}
	return &memoryFile{Reader: bytes.NewReader(data), info: info}, nil
}
func (f fixtureFS) Stat(name string) (fs.FileInfo, error)      { return fs.Stat(f.base, name) }
func (f fixtureFS) ReadDir(name string) ([]fs.DirEntry, error) { return fs.ReadDir(f.base, name) }

type memoryFile struct {
	*bytes.Reader
	info fs.FileInfo
}

func (f *memoryFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *memoryFile) Close() error               { return nil }

func observeLinks(c Case) Observation {
	o := Base(c)
	root, err := os.OpenRoot(os.Getenv("PROBE_TARGET"))
	if err != nil {
		o.Error = err.Error()
		return o
	}
	defer root.Close()
	o.Links = map[string]string{}
	for _, name := range []string{"regular", "inside", "escape", "relative-escape", "cycle-a", "dangling", "Case", "case", "C:\\Windows\\synthetic", "../outside/sentinel"} {
		f, err := root.Open(name)
		if err != nil {
			o.Links[name] = err.Error()
			continue
		}
		f.Close() // Do not read an escaping sentinel even if containment unexpectedly fails.
		o.Links[name] = "opened-without-reading"
		if name == "escape" || name == "relative-escape" || strings.HasPrefix(name, "../") {
			o.Error = "containment failure: escaping path opened"
		}
	}
	o.Diagnostics = []string{"Linux-only controlled os.Root check; not Windows/junction or production walker validation"}
	return o
}

// The outer fixture controller (not the observer) changes this synthetic file
// after a handshake. This demonstrates instability reporting, not race immunity.
func observeChanging(c Case) Observation {
	o := Base(c)
	root, err := os.OpenRoot(os.Getenv("PROBE_TARGET"))
	if err != nil {
		o.Error = err.Error()
		return o
	}
	defer root.Close()
	first, err := root.ReadFile("package.json")
	if err != nil {
		o.Error = err.Error()
		return o
	}
	if err := os.WriteFile("results/"+c.ID+".ready", []byte("ready"), 0600); err != nil {
		o.Error = err.Error()
		return o
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, err := os.Stat("results/" + c.ID + ".changed"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			o.Error = "fixture controller did not respond"
			return o
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, err := root.ReadFile("package.json")
	if err != nil {
		o.Error = err.Error()
		return o
	}
	for _, data := range [][]byte{first, second} {
		child := Observe(Case{ID: c.ID, Extractor: "manifest", Path: "package.json", Content: string(data)})
		o.Children = append(o.Children, child)
		o.Packages = append(o.Packages, child.Packages...)
	}
	if !bytes.Equal(first, second) {
		o.Error = "unstable synthetic file: before/after bytes differ"
	}
	o.Diagnostics = []string{"Deliberate external fixture mutation; no immutable-snapshot or race-resistance claim"}
	return o
}

func observeInstalled(c Case) Observation {
	o := Base(c)
	root, err := os.OpenRoot(os.Getenv("PROBE_TARGET"))
	if err != nil {
		o.Error = err.Error()
		return o
	}
	defer root.Close()
	for _, name := range c.Enumerate {
		f, err := root.Open(name)
		if err != nil {
			o.Error = err.Error()
			continue
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			o.Error = err.Error()
			continue
		}
		if !info.Mode().IsRegular() {
			f.Close()
			o.Error = "non-regular fixture file"
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, MaxInputBytes+1))
		f.Close()
		if err != nil {
			o.Error = err.Error()
			continue
		}
		child := Observe(Case{ID: c.ID + ":" + name, Extractor: "manifest", Path: name, Content: string(b)})
		o.Children = append(o.Children, child)
		o.Packages = append(o.Packages, child.Packages...)
		if child.Error != "" {
			o.Error = child.Error
		}
	}
	o.Diagnostics = []string{"Explicit authored file enumeration, not a production discovery walk"}
	return o
}
