package cli

import "testing"

func TestInteractiveArgumentsKeepMachineAndVerboseModesSeparate(t *testing.T) {
	for _, args := range [][]string{{"scan", "--interactive", "owned"}, {"intel", "status", "--interactive"}, {"intel", "sync", "--interactive"}, {"intel", "import", "--interactive", "owned.bundle"}, {"cache", "prune", "--interactive"}} {
		v, e := ParseArgs(args)
		if e != nil {
			t.Fatal(args, e)
		}
		if args[0] == "scan" {
			if v.Scan.Format != "terminal-interactive" {
				t.Fatal(v)
			}
		} else if v.Intel.Format != "terminal-interactive" {
			t.Fatal(v)
		}
	}
	for _, args := range [][]string{{"scan", "--interactive=yes", "owned"}, {"scan", "--interactive", "--interactive", "owned"}, {"scan", "--interactive", "--format", "json", "owned"}, {"scan", "--interactive", "--verbose", "owned"}, {"intel", "status", "--interactive", "--format", "json"}, {"setup", "--interactive"}, {"intel", "pin", "--interactive", "owned"}} {
		if _, e := ParseArgs(args); e == nil {
			t.Fatal("invalid interactive combination", args)
		}
	}
}
func TestInteractiveProjectionRejectsUnsafeAndUnboundedText(t *testing.T) {
	v := InteractiveView{Summary: "Incomplete", Exit: 3, Rows: []InteractiveRow{{Name: "owned", Version: "1.0.0", State: "REVIEW", Details: "Not confirmed"}}}
	if ValidateInteractiveView(v) != nil {
		t.Fatal("valid projection refused")
	}
	v.Rows[0].Details = "\x1b[31munsafe"
	if ValidateInteractiveView(v) == nil {
		t.Fatal("ANSI source text admitted")
	}
}
