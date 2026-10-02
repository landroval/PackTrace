package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Literal baseline from the approved contract, independent of production helpers.
func argumentWant(path string, provided uint16) Invocation {
	return Invocation{Action: ArgumentAction(1), Scan: ScanArgumentRequest{
		Path: path, Manager: "auto", Checks: ArgumentChecks(7), FailOn: ArgumentChecks(0),
		Format: "terminal", Privacy: "portable", PolicyPath: "", StateDir: "", Output: "-", Provided: ArgumentOptions(provided),
	}}
}

func assertArgument(t *testing.T, args []string, want Invocation, code uint8, index int, option uint16) {
	t.Helper()
	before := append([]string(nil), args...)
	got, err := ParseArgs(args)
	if !reflect.DeepEqual(before, append([]string(nil), args...)) {
		t.Fatal("caller argv changed")
	}
	if code == 0 {
		if err != nil || got != want {
			t.Fatalf("literal request/default-origin expectation lost: got=%#v err=%v want=%#v", got, err, want)
		}
		return
	}
	e, ok := err.(*ArgumentError)
	if !ok || e == nil || e.Code != ArgumentErrorCode(code) || e.ArgIndex != index || e.Option != ArgumentOptions(option) || got != (Invocation{}) {
		t.Fatal("private fatal classification, locator or whole-zero result lost")
	}
	texts := [...]string{"cli: invalid-arguments", "cli: missing-command", "cli: unsupported-command", "cli: control-arguments", "cli: unsupported-option", "cli: repeated-option", "cli: missing-option-value", "cli: invalid-option-value", "cli: missing-root", "cli: invalid-root", "cli: extra-argument", "cli: enforcement-outside-checks"}
	if err.Error() != texts[code] {
		t.Fatal("fixed private error text changed")
	}
}

func TestParseArgsReference(t *testing.T) {
	p06 := Invocation{Action: 1, Scan: ScanArgumentRequest{Path: "root", Manager: "npm@11.6.2", Checks: 5, FailOn: 1, Format: "json", Privacy: "local", PolicyPath: "p.json", StateDir: "s", Output: "r.json", Provided: 255}}
	p09 := argumentWant("p", 6)
	p09.Scan.Checks, p09.Scan.FailOn = 2, 2
	p10 := argumentWant("p", 224)
	p10.Scan.PolicyPath, p10.Scan.StateDir, p10.Scan.Output = "--file", "-", "./-"
	p11 := argumentWant("./a/../ p", 32)
	p11.Scan.PolicyPath = "a=b.json"
	manager := func(value string) Invocation { w := argumentWant("p", 1); w.Scan.Manager = value; return w }
	p20 := argumentWant("p", 8)
	p20.Scan.Format = "sarif"
	cases := []struct {
		name   string
		args   []string
		want   Invocation
		code   uint8
		index  int
		option uint16
	}{
		{"P01", []string{"--help"}, Invocation{Action: 2}, 0, 0, 0},
		{"P02", []string{"scan", "--help"}, Invocation{Action: 3}, 0, 0, 0},
		{"P03", []string{"--version"}, Invocation{Action: 4}, 0, 0, 0},
		{"P04", []string{"scan", "."}, argumentWant(".", 0), 0, 0, 0},
		{"P05", []string{"scan", "--", "--help"}, argumentWant("--help", 0), 0, 0, 0},
		{"P06", []string{"scan", "--manager=npm@11.6.2", "--checks", "integrity,malicious", "--fail-on=malicious", "--format", "json", "--privacy=local", "--policy", "p.json", "--state-dir=s", "--output", "r.json", "root"}, p06, 0, 0, 0},
		{"P07", []string{"scan", "--manager", "auto", "--checks=malicious,vulnerability,integrity", "--fail-on", "none", "--format=terminal", "--privacy", "portable", "--output=-", "p"}, argumentWant("p", 159), 0, 0, 0},
		{"P08", []string{"scan", "--checks=integrity,vulnerability,malicious", "p"}, argumentWant("p", 2), 0, 0, 0},
		{"P09", []string{"scan", "--checks=vulnerability", "--fail-on=vulnerability", "p"}, p09, 0, 0, 0},
		{"P10", []string{"scan", "--policy=--file", "--state-dir", "-", "--output", "./-", "p"}, p10, 0, 0, 0},
		{"P11", []string{"scan", "--policy=a=b.json", "./a/../ p"}, p11, 0, 0, 0},
		{"P12", []string{"scan", `C:\work\project`}, argumentWant(`C:\work\project`, 0), 0, 0, 0},
		{"P13", []string{"scan", "-"}, argumentWant("-", 0), 0, 0, 0},
		{"P14", []string{"scan", "--manager=bun@1.4.2", "p"}, manager("bun@1.4.2"), 0, 0, 0},
		{"P15", []string{"scan", "--manager=npm", "p"}, manager("npm"), 0, 0, 0},
		{"P16", []string{"scan", "--manager=bun", "p"}, manager("bun"), 0, 0, 0},
		{"P17", []string{"scan", "--manager=npm@8.19.4", "p"}, manager("npm@8.19.4"), 0, 0, 0},
		{"P18", []string{"scan", "--manager=npm@10.9.4", "p"}, manager("npm@10.9.4"), 0, 0, 0},
		{"P19", []string{"scan", "--manager=bun@1.3.2", "p"}, manager("bun@1.3.2"), 0, 0, 0},
		{"P20", []string{"scan", "--format=sarif", "p"}, p20, 0, 0, 0},
		{"E01", []string{}, Invocation{}, 1, -1, 0},
		{"E02", []string{"sync"}, Invocation{}, 2, 0, 0},
		{"E03", []string{"--help", "secret-path"}, Invocation{}, 3, 1, 0},
		{"E04", []string{"scan", "--help", "--online"}, Invocation{}, 3, 2, 0},
		{"E05", []string{"scan", "--version"}, Invocation{}, 4, 1, 0},
		{"E06", []string{"scan", "--online", "p"}, Invocation{}, 4, 1, 0},
		{"E07", []string{"scan", "-manager", "npm", "p"}, Invocation{}, 4, 1, 0},
		{"E08", []string{"scan", "--manager=npm", "--manager", "npm", "p"}, Invocation{}, 5, 2, 1},
		{"E09", []string{"scan", "--manager=auto", "--manager"}, Invocation{}, 5, 2, 1},
		{"E10", []string{"scan", "--policy"}, Invocation{}, 6, 1, 32},
		{"E11", []string{"scan", "--policy", "--checks=integrity", "p"}, Invocation{}, 6, 1, 32},
		{"E12", []string{"scan", "--manager=npm@12", "p"}, Invocation{}, 7, 1, 1},
		{"E13", []string{"scan", "--manager", "NPM", "p"}, Invocation{}, 7, 2, 1},
		{"E14", []string{"scan", "--checks=", "p"}, Invocation{}, 7, 1, 2},
		{"E15", []string{"scan", "--checks", "malicious,", "p"}, Invocation{}, 7, 2, 2},
		{"E16", []string{"scan", "--checks=malicious,malicious", "p"}, Invocation{}, 7, 1, 2},
		{"E17", []string{"scan", "--checks=inventory", "p"}, Invocation{}, 7, 1, 2},
		{"E18", []string{"scan", "--checks= malicious", "p"}, Invocation{}, 7, 1, 2},
		{"E19", []string{"scan", "--checks=none", "p"}, Invocation{}, 7, 1, 2},
		{"E20", []string{"scan", "--fail-on=none,integrity", "p"}, Invocation{}, 7, 1, 4},
		{"E21", []string{"scan", "--checks", "malicious", "--fail-on", "integrity", "p"}, Invocation{}, 11, 3, 4},
		{"E22", []string{"scan", "--checks=malicious", "--fail-on=integrity"}, Invocation{}, 8, -1, 0},
		{"E23", []string{"scan"}, Invocation{}, 8, -1, 0},
		{"E24", []string{"scan", "--"}, Invocation{}, 8, -1, 0},
		{"E25", []string{"scan", ""}, Invocation{}, 9, 1, 0},
		{"E26", []string{"scan", "x\x00y"}, Invocation{}, 9, 1, 0},
		{"E27", []string{"scan", "p", "--format=json"}, Invocation{}, 10, 2, 0},
		{"E28", []string{"scan", "--", "p", "q"}, Invocation{}, 10, 3, 0},
		{"E29", []string{"scan", "--policy="}, Invocation{}, 7, 1, 32},
		{"E30", []string{"scan", "--output", "x\x00y", "p"}, Invocation{}, 7, 2, 128},
		{"E31", []string{"scan", "--checks=Malicious", "p"}, Invocation{}, 7, 1, 2},
		{"E32", []string{"scan", "--checks=malicious", "--help"}, Invocation{}, 4, 2, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertArgument(t, tc.args, tc.want, tc.code, tc.index, tc.option) })
	}
}

func TestParseArgsOptions(t *testing.T) {
	options := []struct {
		name, value string
		bit         uint16
		set         func(*ScanArgumentRequest)
	}{
		{"manager", "auto", 1, func(r *ScanArgumentRequest) { r.Manager = "auto" }},
		{"checks", "malicious,vulnerability,integrity", 2, func(r *ScanArgumentRequest) { r.Checks = 7 }},
		{"fail-on", "none", 4, func(r *ScanArgumentRequest) { r.FailOn = 0 }},
		{"format", "terminal", 8, func(r *ScanArgumentRequest) { r.Format = "terminal" }},
		{"privacy", "portable", 16, func(r *ScanArgumentRequest) { r.Privacy = "portable" }},
		{"policy", "policy", 32, func(r *ScanArgumentRequest) { r.PolicyPath = "policy" }},
		{"state-dir", "store", 64, func(r *ScanArgumentRequest) { r.StateDir = "store" }},
		{"output", "-", 128, func(r *ScanArgumentRequest) { r.Output = "-" }},
	}
	for _, o := range options {
		t.Run(o.name, func(t *testing.T) {
			flag := "--" + o.name
			want := argumentWant("p", o.bit)
			o.set(&want.Scan)
			for _, tc := range []struct {
				name  string
				args  []string
				code  uint8
				index int
			}{
				{"split", []string{"scan", flag, o.value, "p"}, 0, 0},
				{"attached", []string{"scan", flag + "=" + o.value, "p"}, 0, 0},
				{"repeated-split", []string{"scan", flag, o.value, flag, o.value, "p"}, 5, 3},
				{"repeated-attached", []string{"scan", flag + "=" + o.value, flag + "=" + o.value, "p"}, 5, 2},
				{"repeated-before-missing", []string{"scan", flag + "=" + o.value, flag}, 5, 2},
				{"repeated-different", []string{"scan", flag, o.value, flag + "=different", "p"}, 5, 3},
				{"repeated-before-invalid", []string{"scan", flag + "=" + o.value, flag + "=", "p"}, 5, 2},
				{"missing", []string{"scan", flag}, 6, 1},
				{"terminator-not-value", []string{"scan", flag, "--", "p"}, 6, 1},
				{"option-not-value", []string{"scan", flag, "--online", "p"}, 6, 1},
				{"empty-split", []string{"scan", flag, "", "p"}, 7, 2},
				{"empty-attached", []string{"scan", flag + "=", "p"}, 7, 1},
				{"nul-split", []string{"scan", flag, "x\x00y", "p"}, 7, 2},
				{"nul-attached", []string{"scan", flag + "=x\x00y", "p"}, 7, 1},
			} {
				t.Run(tc.name, func(t *testing.T) { assertArgument(t, tc.args, want, tc.code, tc.index, o.bit) })
			}
		})
	}
}

func TestParseArgsDefaults(t *testing.T) {
	t.Run("omitted", func(t *testing.T) { assertArgument(t, []string{"scan", "p"}, argumentWant("p", 0), 0, 0, 0) })
	for _, tc := range []struct {
		flag, value string
		bit         uint16
	}{
		{"manager", "auto", 1}, {"checks", "malicious,vulnerability,integrity", 2}, {"fail-on", "none", 4}, {"format", "terminal", 8}, {"privacy", "portable", 16}, {"output", "-", 128},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			assertArgument(t, []string{"scan", "--" + tc.flag + "=" + tc.value, "p"}, argumentWant("p", tc.bit), 0, 0, 0)
		})
	}
}

func TestParseArgsBoundaries(t *testing.T) {
	max := []string{"scan", "--manager", "auto", "--checks", "malicious,vulnerability,integrity", "--fail-on", "none", "--format", "terminal", "--privacy", "portable", "--policy", "policy", "--state-dir", "store", "--output", "-", "--", "p"}
	w := argumentWant("p", 255)
	w.Scan.PolicyPath, w.Scan.StateDir = "policy", "store"
	t.Run("maximal-command", func(t *testing.T) { assertArgument(t, max, w, 0, 0, 0) })
	for _, path := range []string{"--", "-x", "--help", "-", "./a/../ p", "$HOME/p", "~/p", `C:\p`, "https://example.invalid/p", " ", "é", "x\ny", string([]byte{255})} {
		t.Run("literal-"+strconv.Itoa(len(path))+"-"+strconv.Itoa(int(path[0])), func(t *testing.T) {
			assertArgument(t, []string{"scan", "--", path}, argumentWant(path, 0), 0, 0, 0)
			if !strings.HasPrefix(path, "-") || path == "-" {
				assertArgument(t, []string{"scan", path}, argumentWant(path, 0), 0, 0, 0)
			}
			for _, option := range []struct {
				name string
				bit  uint16
				set  func(*ScanArgumentRequest)
			}{
				{"policy", 32, func(r *ScanArgumentRequest) { r.PolicyPath = path }},
				{"state-dir", 64, func(r *ScanArgumentRequest) { r.StateDir = path }},
				{"output", 128, func(r *ScanArgumentRequest) { r.Output = path }},
			} {
				want := argumentWant("p", option.bit)
				option.set(&want.Scan)
				assertArgument(t, []string{"scan", "--" + option.name + "=" + path, "p"}, want, 0, 0, 0)
			}
		})
	}
	for i, text := range []string{"", ",malicious", "malicious,", "malicious,,integrity", "malicious,malicious", "malicious,vulnerability,integrity,malicious", "inventory", "none,malicious", "Malicious", " malicious", "malicious ", "x\x00y"} {
		t.Run("invalid-category-"+strconv.Itoa(i), func(t *testing.T) {
			for _, option := range []struct {
				name string
				bit  uint16
			}{{"checks", 2}, {"fail-on", 4}} {
				assertArgument(t, []string{"scan", "--" + option.name + "=" + text, "p"}, Invocation{}, 7, 1, option.bit)
			}
		})
	}
	for i, text := range []string{"malicious,vulnerability,integrity", "malicious,integrity,vulnerability", "vulnerability,malicious,integrity", "vulnerability,integrity,malicious", "integrity,malicious,vulnerability", "integrity,vulnerability,malicious"} {
		t.Run("category-permutation-"+strconv.Itoa(i), func(t *testing.T) {
			assertArgument(t, []string{"scan", "--checks=" + text, "p"}, argumentWant("p", 2), 0, 0, 0)
			want := argumentWant("p", 4)
			want.Scan.FailOn = 7
			assertArgument(t, []string{"scan", "--fail-on=" + text, "p"}, want, 0, 0, 0)
		})
	}
	for i, args := range [][]string{nil, {""}, {"help"}, {"version"}, {"-h"}, {"-v"}, {"--help=x"}, {"--version", "p"}, {"scan", "-x"}, {"scan", "--=x"}, {"scan", "--output=x", "--help"}, {"scan", "--", ""}, {"scan", "--", "x\x00y"}, {"scan", "p", "--help"}} {
		codes := []uint8{1, 2, 2, 2, 2, 2, 2, 3, 4, 4, 4, 9, 9, 10}
		indices := []int{-1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 2}
		t.Run("control-root-"+strconv.Itoa(i), func(t *testing.T) { assertArgument(t, args, Invocation{}, codes[i], indices[i], 0) })
	}
	for i, flag := range []string{"--manager= auto", "--format=JSON", "--privacy=LOCAL", "--fail-on=NONE", "--checks=none"} {
		bits := []uint16{1, 8, 16, 4, 2}
		t.Run("exact-value-"+strconv.Itoa(i), func(t *testing.T) { assertArgument(t, []string{"scan", flag, "p"}, Invocation{}, 7, 1, bits[i]) })
	}
	t.Run("first-equals", func(t *testing.T) {
		want := argumentWant("p", 32)
		want.Scan.PolicyPath = "a=b=c"
		assertArgument(t, []string{"scan", "--policy=a=b=c", "p"}, want, 0, 0, 0)
	})
}

func TestParseArgsScope(t *testing.T) {
	want := argumentWant("root", 52)
	want.Scan.PolicyPath = "p"
	want.Scan.Privacy = "local"
	t.Run("not-effective-policy", func(t *testing.T) {
		assertArgument(t, []string{"scan", "--policy=p", "--privacy=local", "--fail-on=none", "root"}, want, 0, 0, 0)
	})
	for checks := uint8(1); checks < 8; checks++ {
		for fail := uint8(1); fail < 8; fail++ {
			t.Run(fmt.Sprintf("checks-%d-fail-%d", checks, fail), func(t *testing.T) {
				texts := []string{"", "malicious", "vulnerability", "malicious,vulnerability", "integrity", "malicious,integrity", "vulnerability,integrity", "malicious,vulnerability,integrity"}
				args := []string{"scan", "--checks=" + texts[checks], "--fail-on=" + texts[fail], "p"}
				// Hand-qualified allowed memberships, not a call to the production validator.
				allowed := map[uint8][]uint8{1: {1}, 2: {2}, 3: {1, 2, 3}, 4: {4}, 5: {1, 4, 5}, 6: {2, 4, 6}, 7: {1, 2, 3, 4, 5, 6, 7}}
				ok := false
				for _, f := range allowed[checks] {
					if f == fail {
						ok = true
					}
				}
				if !ok {
					assertArgument(t, args, Invocation{}, 11, 2, 4)
					return
				}
				w := argumentWant("p", 6)
				w.Scan.Checks = ArgumentChecks(checks)
				w.Scan.FailOn = ArgumentChecks(fail)
				assertArgument(t, args, w, 0, 0, 0)
			})
		}
	}
	for i, args := range [][]string{{"scan", "--checks=malicious", "--fail-on=integrity"}, {"scan", "--checks=malicious", "--fail-on=integrity", ""}, {"scan", "--checks=malicious", "--fail-on=integrity", "p", "q"}} {
		codes := []uint8{8, 9, 10}
		indices := []int{-1, 3, 4}
		t.Run("root-priority-"+strconv.Itoa(i), func(t *testing.T) { assertArgument(t, args, Invocation{}, codes[i], indices[i], 0) })
	}
}

func TestParseArgsPrivacy(t *testing.T) {
	marker := "PACKTRACE_SYNTHETIC_SECRET\x1b[31m\n"
	for i, args := range [][]string{{marker}, {"scan", "--" + marker}, {"scan", "--manager=" + marker, "p"}, {"scan", "--checks=" + marker, "p"}, {"scan", "--policy=" + marker, "--output="}, {"scan", "--policy=" + marker, "x\x00"}} {
		codes := []uint8{2, 4, 7, 7, 7, 9}
		indices := []int{0, 1, 1, 1, 2, 2}
		bits := []uint16{0, 0, 1, 2, 128, 0}
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			assertArgument(t, args, Invocation{}, codes[i], indices[i], bits[i])
			_, err := ParseArgs(args)
			for _, text := range []string{err.Error(), fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
				if strings.Contains(text, marker) || strings.Contains(text, "PACKTRACE_SYNTHETIC_SECRET") {
					t.Fatal("rejected private marker disclosed")
				}
			}
		})
	}
}

func TestParseArgsOwnership(t *testing.T) {
	args := []string{"scan", "--policy=relative-secret", "--", "./p/../q"}
	want := argumentWant("./p/../q", 32)
	want.Scan.PolicyPath = "relative-secret"
	assertArgument(t, args, want, 0, 0, 0)
	got, err := ParseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	for i := range args {
		args[i] = "changed"
	}
	if got != want {
		t.Fatal("request aliases mutable argv container")
	}
	assertArgument(t, []string{"scan", "another"}, argumentWant("another", 0), 0, 0, 0)
	if got != want {
		t.Fatal("calls share mutable state")
	}
}

func TestArgumentErrorLayout(t *testing.T) {
	for i, v := range []ArgumentAction{ArgumentActionUnknown, ArgumentActionScan, ArgumentActionHelp, ArgumentActionScanHelp, ArgumentActionVersion} {
		if v != ArgumentAction(i) {
			t.Fatal("action protocol changed")
		}
	}
	for i, v := range []ArgumentChecks{ArgumentCheckMalicious, ArgumentCheckVulnerability, ArgumentCheckIntegrity} {
		if v != ArgumentChecks(1<<i) {
			t.Fatal("category membership protocol changed")
		}
	}
	for i, v := range []ArgumentOptions{ArgumentOptionManager, ArgumentOptionChecks, ArgumentOptionFailOn, ArgumentOptionFormat, ArgumentOptionPrivacy, ArgumentOptionPolicy, ArgumentOptionStateDir, ArgumentOptionOutput} {
		if v != ArgumentOptions(1<<i) {
			t.Fatal("origin protocol changed")
		}
	}
	codes := []ArgumentErrorCode{ArgumentErrorUnknown, ArgumentErrorMissingCommand, ArgumentErrorCommandUnsupported, ArgumentErrorControlArguments, ArgumentErrorOptionUnsupported, ArgumentErrorOptionRepeated, ArgumentErrorOptionMissingValue, ArgumentErrorOptionValueInvalid, ArgumentErrorRootMissing, ArgumentErrorRootInvalid, ArgumentErrorExtraArgument, ArgumentErrorEnforcementOutsideChecks}
	texts := []string{"cli: invalid-arguments", "cli: missing-command", "cli: unsupported-command", "cli: control-arguments", "cli: unsupported-option", "cli: repeated-option", "cli: missing-option-value", "cli: invalid-option-value", "cli: missing-root", "cli: invalid-root", "cli: extra-argument", "cli: enforcement-outside-checks"}
	for i, code := range codes {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if code != ArgumentErrorCode(i) || (&ArgumentError{Code: code, ArgIndex: 999, Option: 255}).Error() != texts[i] {
				t.Fatal("fixed error protocol or privacy changed")
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		if (&ArgumentError{Code: 255}).Error() != "cli: invalid-arguments" {
			t.Fatal("unknown code not safely rendered")
		}
	})
}

func TestParseArgsSeparation(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "arguments.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, im := range f.Imports {
		if im.Path.Value != `"strings"` {
			t.Fatal("production import crosses pure parser scope")
		}
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok == token.VAR {
				t.Fatal("global mutable state")
			}
		case *ast.FuncDecl:
			if d.Name.Name == "init" {
				t.Fatal("implicit execution")
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			t.Fatal("unrequested concurrency")
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println" || id.Name == "SelectScanExit") {
				t.Fatal("parser prints or invents exit decisions")
			}
		}
		return true
	})
	for _, tc := range []struct {
		typ   reflect.Type
		names []string
	}{{reflect.TypeOf(ArgumentError{}), []string{"Code", "ArgIndex", "Option"}}, {reflect.TypeOf(Invocation{}), []string{"Action", "Scan"}}, {reflect.TypeOf(ScanArgumentRequest{}), []string{"Path", "Manager", "Format", "Privacy", "PolicyPath", "StateDir", "Output", "Checks", "FailOn", "Provided"}}} {
		if tc.typ.NumField() != len(tc.names) {
			t.Fatal("unapproved/raw result or error extension")
		}
		for i, name := range tc.names {
			if tc.typ.Field(i).Name != name {
				t.Fatal("unapproved field")
			}
		}
	}
}
