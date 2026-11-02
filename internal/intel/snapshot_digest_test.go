package intel

import "testing"

func TestSnapshotDigestRequiresSingleCanonicalSHA256(t *testing.T) {
	if _, e := ParseSnapshotDigest("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"sha1-Zm9v", "sha256-a sha256-b", "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", " sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if _, e := ParseSnapshotDigest(s); e == nil {
			t.Fatal("weak or noncanonical descriptor pin admitted")
		}
	}
}
