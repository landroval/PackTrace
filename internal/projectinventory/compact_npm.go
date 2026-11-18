package projectinventory

import (
	"reflect"
	"strconv"
	"strings"

	"packtrace/internal/inventory"
	"packtrace/internal/managerprofile"
)

// CompactNPMRoot transfers originals and native receipts, not a serialized
// semantic model. Only successful, flat registry acquisitions have this profile.
// Receipt presence has the same native acquisition boundary as legacy Evidence;
// neither public JSON nor a worker qualification boolean supplies authority.
type CompactNPMRoot struct {
	Selection Selection
	Inputs    []OriginalInput
	Receipts  []NPMRootReceipt
}

type NPMRootReceipt struct {
	Source   uint32
	Location string
	Method   string
	SHA256   [32]byte
}

const maxCompactNPMInstances = 1024
const maxCompactNPMGraph = 8192

// CompactNPMOriginal only selects the profile if strict reconstruction preserves
// the entire legacy private model. Unsupported shapes keep the prior path.
func CompactNPMOriginal(r Result) (CompactNPMRoot, bool) {
	r = PrivateOriginal(r)
	v := CompactNPMRoot{Selection: r.Selection, Inputs: r.OriginalInputs}
	for _, e := range r.Model.Evidence {
		if !e.Complete {
			return CompactNPMRoot{}, false
		}
		v.Receipts = append(v.Receipts, NPMRootReceipt{e.ID, e.Location, e.Method, e.SHA256})
	}
	rebuilt, err := ExpandCompactNPM(v)
	r.Metadata = rebuilt.Metadata // Live discovery is never an IPC field.
	return v, err == nil && reflect.DeepEqual(rebuilt, r)
}

// ExpandCompactNPM independently bounds both raw material and reconstructed work.
// Numeric public inventory is joined afterwards with ValidateOriginalClaims; it
// is never used to invent names, paths, hashes, declarations or native leases.
func ExpandCompactNPM(v CompactNPMRoot) (Result, error) {
	bad := func() (Result, error) { return Result{}, ErrWire }
	if !managerprofile.SupportsNPM(v.Selection.Profile) || v.Selection.Family != "npm" || v.Selection.State != "usable" || v.Selection.Reason != "none" || !allowed(v.Selection.File, "package-lock.json", "npm-shrinkwrap.json") || len(v.Inputs) < 2 || len(v.Inputs) > maxCompactNPMInstances+2 || len(v.Receipts) != 2*len(v.Inputs)-1 {
		return bad()
	}
	raw := map[uint32][]byte{}
	total := 0
	for _, in := range v.Inputs {
		total += len(in.Bytes)
		if total > maxOriginalInputBytes || len(in.Bytes) == 0 || raw[in.Source] != nil {
			return bad()
		}
		raw[in.Source] = in.Bytes
	}
	c := collector{requirementsRemaining: 4096, classCounts: map[string]int{}, workspaceScopes: map[string]Scope{}}
	c.result.Selection = v.Selection
	c.result.OriginalInputs = v.Inputs
	c.result.Model.Scopes = []Scope{{ID: 1, Kind: "project", Status: "complete"}}
	byPath := map[string]uint32{}
	var root, lock uint32
	for i, e := range v.Receipts {
		if e.Source != uint32(i+1) {
			return bad()
		}
		if _, exists := byPath[e.Location]; exists {
			return bad()
		}
		byPath[e.Location] = e.Source
		switch e.Method {
		case "native-metadata":
			if i != 0 || e.Location != "" || e.SHA256 != ([32]byte{}) || raw[e.Source] != nil {
				return bad()
			}
		case "native-metadata-lease":
			if !flatNPMPath(e.Location) || e.SHA256 != ([32]byte{}) || raw[e.Source] != nil {
				return bad()
			}
		case "native-input-lease":
			if raw[e.Source] == nil {
				return bad()
			}
			switch e.Location {
			case "package.json":
				root = e.Source
			case v.Selection.File:
				lock = e.Source
			default:
				if !strings.HasSuffix(e.Location, "/package.json") || !flatNPMPath(strings.TrimSuffix(e.Location, "/package.json")) {
					return bad()
				}
			}
		default:
			return bad()
		}
		c.result.Model.Evidence = append(c.result.Model.Evidence, Evidence{ID: e.Source, Scope: 1, Location: e.Location, Method: e.Method, SHA256: e.SHA256, Complete: true})
	}
	if root != 2 || lock != 3 || v.Receipts[0].Method != "native-metadata" || len(raw) != len(v.Inputs) {
		return bad()
	}
	doc, err := inventory.ParseManifest(raw[root])
	if err != nil {
		return bad()
	}
	if _, ok := doc.Fields["workspaces"]; ok {
		return bad()
	}
	if c.projectManifest(1, root, "package.json", doc) != nil {
		return bad()
	}
	lockDoc, err := inventory.ParseNPMLock(raw[lock])
	if err != nil || len(lockDoc.Packages) > maxCompactNPMInstances+1 {
		return bad()
	}
	if c.projectNPM(lockDoc, lock) != nil {
		return bad()
	}
	for _, o := range c.result.Model.Observations {
		if o.Class == "locked" && o.Kind != "project" && (!flatNPMPath(o.Location) || o.Kind != "url" || !strings.HasPrefix(o.Origin, "https://registry.npmjs.org/")) {
			return bad()
		}
	}
	for _, e := range v.Receipts {
		if e.Method != "native-metadata-lease" {
			continue
		}
		source := byPath[e.Location+"/package.json"]
		if source != e.Source+1 || raw[source] == nil {
			return bad()
		}
		own, err := inventory.ParseManifest(raw[source])
		if err != nil {
			return bad()
		}
		groups, err := inventory.ProjectManifest(own)
		if err != nil {
			return bad()
		}
		name, ns := claimString(own.Fields, "name")
		version, vs := claimString(own.Fields, "version")
		if ns != "value" || vs != "value" || !c.chargeRequirements(1, source, groups.Groups) {
			return bad()
		}
		c.add(Observation{Workspace: 1, Source: source, Class: "installed", Kind: "directory", Status: "complete", Location: e.Location, Name: name, Version: version, Fields: map[string]string{"installation-name": installationName(e.Location), "metadata-evidence": strconv.Itoa(int(e.Source)), "physical-target": e.Location, "name-state": ns, "version-state": vs}, Requirements: groups.Groups})
	}
	if len(c.result.Model.Observations) > 4096 || len(c.result.Model.Gaps) != 0 {
		return bad()
	}
	c.result.Model = Reconcile(c.result.Model)
	c.result.Complete = true
	r := PrivateOriginal(c.result)
	if len(r.Model.Observations)+len(r.Model.Evidence)+len(r.Model.Relations) > maxCompactNPMGraph || len(r.Model.Gaps) != 0 || ValidateOriginalBytes(r) != nil {
		return bad()
	}
	return r, nil
}

func flatNPMPath(p string) bool {
	if !strings.HasPrefix(p, "node_modules/") {
		return false
	}
	name := strings.TrimPrefix(p, "node_modules/")
	parts := strings.Split(name, "/")
	if len(parts) == 2 && strings.HasPrefix(parts[0], "@") && len(parts[0]) > 1 {
		parts = parts[1:]
	}
	return len(parts) == 1 && parts[0] != "" && parts[0] != "." && parts[0] != ".." && !strings.ContainsAny(name, "\\\x00")
}
