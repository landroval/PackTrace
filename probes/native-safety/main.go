package main

import (
	"io"
	"os"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--observer" {
		os.Exit(observer())
	}
	os.Exit(run(os.Args[1:], os.Stdout))
}
func run(args []string, out io.Writer) int {
	r := baseReceipt(actualEnvironment())
	if len(args) != 2 || args[0] != "--evidence-dir" || args[1] == "" {
		r.Environment.Reason = "invalid-arguments"
		r.Status = "FAIL"
		if emit(out, r) != nil {
			return 2
		}
		return 2
	}
	if !profileOK(r.Environment) {
		r.Environment.Reason = "unsupported-profile"
		if emit(out, r) != nil {
			return 2
		}
		return 3
	}
	code := nativeRun(args[1], &r)
	if !validReceipt(r, code) {
		r.Status = "FAIL"
		code = 2
	}
	if emit(out, r) != nil {
		return 2
	}
	return code
}
