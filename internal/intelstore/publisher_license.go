package intelstore

// Only fixed operator-reviewed OSV publisher profiles enter the portable graph.
// A namespace mapping is not publisher authentication or a blanket data license.
type publisherLicense struct {
	count                                        uint64
	publisher, license, origin, licenseURL, hash string
	text                                         []byte
}

const sourceChanges = "OSV serves enriched records; PackTrace preserves received original bytes and adds local indexes. Original credits/notices remain in those bytes. No publisher endorsement or signature is asserted."

func knownPublisherCounts(p preparationRecord) bool {
	if p.Records > 2_000_000 || p.UnknownPublisherRecords != 0 {
		return false
	}
	remaining := p.Records
	for _, count := range []uint64{p.GitHubRecords, p.OpenSSFRecords, p.EEFRecords, p.GSDRecords} {
		if count > remaining {
			return false
		}
		remaining -= count
	}
	return remaining == 0
}
func publisherLicenses(p preparationRecord) [4]publisherLicense {
	return [4]publisherLicense{
		{p.GitHubRecords, "GitHub Advisory Database", "CC-BY-4.0", "https://github.com/github/advisory-database", "https://github.com/github/advisory-database/blob/main/LICENSE.md", "9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94", githubLicense},
		{p.OpenSSFRecords, "OpenSSF Malicious Packages contributors", "Apache-2.0", "https://github.com/ossf/malicious-packages", "https://github.com/ossf/malicious-packages/blob/main/LICENSE", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4", openssfLicense},
		// CC-BY's verbatim legal code is shared; attribution and data-license grant
		// are separate from GitHub's. EEF's grant covers its OSV, not others' ADP.
		{p.EEFRecords, "Erlang Ecosystem Foundation CNA", "CC-BY-4.0", "https://cna.erlef.org/", "https://cna.erlef.org/data-licensing/", "9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94", githubLicense},
		{p.GSDRecords, "Global Security Database contributors", "CC0-1.0", "https://github.com/cloudsecurityalliance/gsd-database", "https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE", "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499", gsdLicense},
	}
}
