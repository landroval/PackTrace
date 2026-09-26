// This command alone imports the graph enricher so its footprint is measurable.
package main

import (
	"context"
	"sort"

	"github.com/google/osv-scalibr/enricher/transitivedependency/nodemodules"
	"github.com/google/osv-scalibr/inventory"
	probe "packtrace.local/scalibr-inventory-probe"
)

func main() {
	c := probe.ReadCase()
	o := probe.Base(c)
	inv := inventory.Inventory{}
	paths := make([]string, 0, len(c.Files))
	for path := range c.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		child, packages := probe.Extract(probe.Case{ID: c.ID + ":" + path, Extractor: "manifest", Path: path, Content: c.Files[path]})
		o.Children = append(o.Children, child)
		if child.Error != "" {
			o.Error = child.Error
			probe.Print(o)
			return
		}
		for _, p := range packages.Packages {
			p.ID = path // Deterministic probe ID, not an upstream or product fingerprint.
		}
		inv.Packages = append(inv.Packages, packages.Packages...)
	}
	e, err := nodemodules.New(nil)
	if err == nil {
		err = e.Enrich(context.Background(), nil, &inv)
	}
	if err != nil {
		o.Error = err.Error()
	}
	o.Packages = probe.Normalize(inv)
	o.Diagnostics = []string{"ParentIDs are upstream constraint matches, not validated Node/Bun resolution paths"}
	probe.Print(o)
}
