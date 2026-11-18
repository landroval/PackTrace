package execution

import (
	"encoding/json"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

func bunOriginalWanted(p *integrityscan.Plan) bool {
	return p != nil && p.Checks&(cli.ArgumentCheckIntegrity|cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) != 0
}

// Original acquisition and exception material share the existing private byte
// and row ceilings, as well as the channel's cumulative frame/traffic budget.
// A witness too large for one existing frame abstains; it never renews a budget.
func (b *scanPolicyMaterialBuffer) addOriginal(r projectinventory.Result) error {
	rows := len(r.Model.Observations) + len(r.Model.Evidence) + len(r.OriginalInputs)
	if b.closed || b.originalRows != 0 || rows == 0 || rows > integrityscan.MaxPolicyMaterials-len(b.rows) || projectinventory.ValidateOriginalBytes(r) != nil {
		return errScanProtocol
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > maxMessage-4096 || len(encoded) > integrityscan.MaxPolicyMaterialBytes-b.bytes {
		return errScanProtocol
	}
	b.originalRows = rows
	b.bytes += len(encoded)
	return nil
}

// addCompactNPM counts each unique retained input, native receipt and selection
// primitive, not a bundled semantic graph. Witnesses consume the same budget.
func (b *scanPolicyMaterialBuffer) addCompactNPM(v projectinventory.CompactNPMRoot) (projectinventory.Result, error) {
	rows := len(v.Inputs) + len(v.Receipts) + 1
	if b.closed || b.originalRows != 0 || rows > integrityscan.MaxPolicyMaterials-len(b.rows) {
		return projectinventory.Result{}, errScanProtocol
	}
	encoded, err := json.Marshal(v)
	if err != nil || len(encoded) > maxMessage-4096 || len(encoded) > integrityscan.MaxPolicyMaterialBytes-b.bytes {
		return projectinventory.Result{}, errScanProtocol
	}
	r, err := projectinventory.ExpandCompactNPM(v)
	if err != nil {
		return projectinventory.Result{}, errScanProtocol
	}
	b.originalRows = rows
	b.bytes += len(encoded)
	return r, nil
}

func (b *scanPolicyMaterialBuffer) emitOriginal(send func(string, any) error, r projectinventory.Result) (bool, error) {
	if v, ok := projectinventory.CompactNPMOriginal(r); ok {
		if _, err := b.addCompactNPM(v); err != nil {
			return false, nil
		}
		if err := send("npm-root-original", v); err != nil {
			return false, err
		}
		return true, nil
	}
	return b.emitLegacyOriginal(send, r)
}

func (b *scanPolicyMaterialBuffer) emitLegacyOriginal(send func(string, any) error, r projectinventory.Result) (bool, error) {
	if (r.Selection.Family != "bun" && r.Selection.Family != "npm") || len(r.Model.Observations)+len(r.Model.Evidence)+len(r.OriginalInputs) > integrityscan.MaxPolicyMaterials-len(b.rows) {
		return false, nil
	}
	r = projectinventory.PrivateOriginal(r)
	if b.addOriginal(r) != nil {
		return false, nil
	}
	if err := send("bun-original", r); err != nil {
		return false, err
	}
	return true, nil
}
