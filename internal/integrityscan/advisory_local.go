package integrityscan

import (
	"encoding/hex"
	"regexp"

	"packtrace/internal/intel"
	"packtrace/internal/projectinventory"
)

// These additional investigative details are admitted only for explicit local
// output. They never authorize origin correspondence or enter portable frames.
type LocalObservation struct {
	Observation uint32 `json:"observation"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Location    string `json:"location"`
}
type LocalAdvisory struct {
	Advisory int    `json:"advisory"`
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
}
type LocalDetails struct {
	Observations []LocalObservation `json:"observations"`
	Advisories   []LocalAdvisory    `json:"advisories"`
	Limited      bool               `json:"limited"`
}

const maxLocalAdvisoryIDBytes = 256

var localAdvisoryID = regexp.MustCompile(`\A(?:MAL-[0-9]{4}-[0-9]+|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-[0-9]{4}-[0-9]{4,}|EEF-CVE-[0-9]{4}-[0-9]{4,}|GSD-[0-9]{4}-[0-9]+)\z`)

func localAdvisoryRecord(record intel.SnapshotOriginalEvidence, index int) LocalAdvisory {
	id := record.Header.ID.Value
	if len(id) > maxLocalAdvisoryIDBytes || !localAdvisoryID.MatchString(id) {
		id = ""
	}
	return LocalAdvisory{Advisory: index, ID: id, SHA256: hex.EncodeToString(record.SHA256[:])}
}
func ValidateLocalAdvisory(v LocalAdvisory) error {
	hash, e := hex.DecodeString(v.SHA256)
	if v.Advisory < 1 || v.Advisory > 4096 || e != nil || len(hash) != 32 || [32]byte(hash) == ([32]byte{}) || hex.EncodeToString(hash) != v.SHA256 || (len(v.ID) > maxLocalAdvisoryIDBytes || v.ID != "" && !localAdvisoryID.MatchString(v.ID)) {
		return ErrAdvisory
	}
	return nil
}
func ValidateLocalObservation(v LocalObservation, inventory projectinventory.PublicInventory) error {
	if v.Observation == 0 || int(v.Observation) > len(inventory.Observations) {
		return ErrAdvisory
	}
	o := inventory.Observations[v.Observation-1]
	if o.ID != v.Observation || !oneOf(o.Class, "locked", "installed") || o.Kind == "project" || (v.Name != "" && !canonicalNPMName(v.Name)) || len(v.Version) > 256 || (v.Location != "" && !relative(v.Location)) {
		return ErrAdvisory
	}
	if v.Version != "" {
		if _, e := intel.ParseSemVer(v.Version); e != nil {
			return ErrAdvisory
		}
	}
	return nil
}

func localDetailMaps(details *LocalDetails) (map[uint32]LocalObservation, map[int]LocalAdvisory) {
	observations := map[uint32]LocalObservation{}
	advisories := map[int]LocalAdvisory{}
	if details != nil {
		for _, observation := range details.Observations {
			observations[observation.Observation] = observation
		}
		for _, advisory := range details.Advisories {
			advisories[advisory.Advisory] = advisory
		}
	}
	return observations, advisories
}

func PlanPrivacy(plan Plan) string {
	if plan.Privacy == "" {
		return "portable"
	}
	return plan.Privacy
}

func ValidateLocalDetails(details LocalDetails, decisions []AdvisoryDecision, inventory projectinventory.PublicInventory) error {
	if details.Observations == nil || details.Advisories == nil || len(details.Observations) > 4096 || len(details.Advisories) > 4096 {
		return ErrAdvisory
	}
	observations := map[uint32]bool{}
	var last uint32
	for _, v := range details.Observations {
		if v.Observation <= last || ValidateLocalObservation(v, inventory) != nil {
			return ErrAdvisory
		}
		last = v.Observation
		observations[v.Observation] = true
	}
	for i, v := range details.Advisories {
		if v.Advisory != i+1 || ValidateLocalAdvisory(v) != nil {
			return ErrAdvisory
		}
	}
	maxAdvisory := 0
	for _, d := range decisions {
		if d.Advisory > len(details.Advisories) || (!details.Limited && !observations[d.Observation]) {
			return ErrAdvisory
		}
		maxAdvisory = max(maxAdvisory, d.Advisory)
	}
	if maxAdvisory != len(details.Advisories) {
		return ErrAdvisory
	}
	return nil
}

func CollectLocalObservations(result projectinventory.Result) LocalDetails {
	details := LocalDetails{Observations: []LocalObservation{}, Advisories: []LocalAdvisory{}}
	for _, o := range result.Model.Observations {
		if !oneOf(o.Class, "locked", "installed") || o.Kind == "project" {
			continue
		}
		if len(details.Observations) == 4096 {
			details.Limited = true
			break
		}
		d := LocalObservation{Observation: o.ID}
		if canonicalNPMName(o.Name) {
			d.Name = o.Name
		}
		if len(o.Version) <= 256 {
			if _, e := intel.ParseSemVer(o.Version); e == nil {
				d.Version = o.Version
			}
		}
		if relative(o.Location) {
			d.Location = o.Location
		}
		details.Observations = append(details.Observations, d)
	}
	return details
}
