package offlineintegrity

import "testing"

func TestQualificationSetupRequiresBoundProvenance(t *testing.T) {
	good := Setup{SourceSHA: "0123456789abcdef0123456789abcdef01234567", ExpectedSHA: "0123456789abcdef0123456789abcdef01234567", GoVersion: "go1.27.1", GoArtifactSHA256: hex64, BuildFlags: "-tags=nativequalification", OS: "darwin", Arch: "arm64", OSVersion: "15.8", Kernel: "24.6", Filesystem: "apfs", SDKChecksum: hex64, SDK: "MacOSX15.sdk", UID: "501", Profile: "owned-fixtures-v1"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	cases := []Setup{good, good, good, good, good, good, good, good, good}
	cases[0].SourceSHA = ""
	cases[1].ExpectedSHA = "ffffffffffffffffffffffffffffffffffffffff"
	cases[2].GoVersion = "go1.27.3-X:nodwarf5"
	cases[3].SDKChecksum = ""
	cases[4].Profile = ""
	cases[5].Filesystem = ""
	cases[6].Kernel = ""
	cases[7].GoArtifactSHA256 = ""
	cases[8].OSVersion = "14.0"
	for i, s := range cases {
		if s.validate() == nil {
			t.Fatalf("accepted missing prerequisite %d", i)
		}
	}
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
