package main

import probe "packtrace.local/scalibr-inventory-probe"

func main() {
	probe.Print(probe.Observe(probe.ReadCase()))
}
