package integrityscan

import (
	"fmt"
	"packtrace/internal/cli"
	"strings"
)

// BuildInteractiveView first performs the same frozen-authority/privacy checks
// as terminal publication. A saved JSON report cannot enter this path.
func BuildInteractiveView(r Report) (cli.InteractiveView, error) {
	summary, err := Render(r, "terminal")
	if err != nil {
		return cli.InteractiveView{}, err
	}
	view := cli.InteractiveView{Summary: string(summary), Exit: r.ExitCode, Rows: []cli.InteractiveRow{}}
	if a := r.Advisories; a != nil {
		classes := map[uint32]string{}
		if r.Inventory != nil {
			for _, o := range r.Inventory.Observations {
				classes[o.ID] = o.Class
			}
		}
		observations, originals := localDetailMaps(a.Local)
		for _, candidate := range []bool{false, true} {
			for _, g := range advisoryTerminalGroups(a, classes, candidate) {
				var detail strings.Builder
				state := "FINDING"
				if candidate {
					state = "REVIEW"
				}
				fmt.Fprintf(&detail, "%s@%s [%s]\n\nEvidence rows remain separate; record counts are not incidents or severity.\nAccepted findings stay visible; acceptance/enforcement totals are in Summary.\n", terminalCell(g.pkg.name, 256), terminalCell(g.pkg.version, 256), state)
				// ponytail: bounded 4096-row scan per display group; index only if measured large reports need it.
				for _, d := range a.Decisions {
					if candidate && !d.Candidate || !candidate && !d.EnforcementEligible {
						continue
					}
					o := observations[d.Observation]
					if g.pkg.unknown != 0 {
						if d.Observation != g.pkg.unknown {
							continue
						}
					} else if o.Name != g.pkg.name || o.Version != g.pkg.version {
						continue
					}
					fmt.Fprintf(&detail, "\nObservation #%d (%s) | original #%d | affected entry %d\nOrigin: %s | Version condition: %s | Fully evaluated: %t\n", d.Observation, classes[d.Observation], d.Advisory, d.Affected, d.Origin, d.VersionOutcome, d.FullyEvaluated)
					if r.Privacy == "local" {
						original := originals[d.Advisory]
						fmt.Fprintf(&detail, "Advisory: %s\n", terminalCell(original.ID, 256))
						if original.Summary != "" {
							fmt.Fprintf(&detail, "Advisory says: %s\n", terminalCell(original.Summary, 320))
						}
						reason, next := localMatchReason(d, o, original)
						fmt.Fprintf(&detail, "Why: %s\nNext: %s\n", reason, next)
					} else {
						fmt.Fprintln(&detail, "Identities and advisory text are hidden by portable privacy.")
					}
				}
				view.Rows = append(view.Rows, cli.InteractiveRow{Name: terminalCell(g.pkg.name, 256), Version: terminalCell(g.pkg.version, 256), State: state, Details: detail.String()})
			}
		}
	}
	if err = cli.ValidateInteractiveView(view); err != nil {
		return cli.InteractiveView{}, err
	}
	return view, nil
}
