package execution

import (
	"encoding/json"

	"packtrace/internal/cli"
	"packtrace/internal/integrityscan"
	"packtrace/internal/projectinventory"
)

func bunOriginalWanted(p *integrityscan.Plan) bool {
	return p != nil && len(p.Policy.BunOrigins) != 0 && p.Checks&(cli.ArgumentCheckMalicious|cli.ArgumentCheckVulnerability) != 0
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

func (b *scanPolicyMaterialBuffer) emitOriginal(send func(string, any) error, r projectinventory.Result) (bool, error) {
	if r.Selection.Family != "bun" || len(r.Model.Observations)+len(r.Model.Evidence)+len(r.OriginalInputs) > integrityscan.MaxPolicyMaterials-len(b.rows) {
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
