package cli

import "testing"

func TestSetupArguments(t *testing.T) {
	for _, args := range [][]string{
		{"setup", "--help"},
		{"setup", "--policy", "/operator/policy.json"},
		{"setup", "--policy=/operator/policy.json", "--state-dir=/state", "--privacy=portable"},
	} {
		if _, err := ParseArgs(args); err != nil {
			t.Fatalf("native setup command rejected: %v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"setup", "--help", "extra"},
		{"setup", "--policy"},
		{"setup", "--policy=a", "--policy=b"},
		{"setup", "--output=somewhere"},
		{"setup", "--privacy=public"},
		{"setup", "target"},
	} {
		if _, err := ParseArgs(args); err == nil {
			t.Fatalf("unsafe/ambiguous setup accepted: %v", args)
		}
	}
}
