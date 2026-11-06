package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
)

func corpusShardSelection(profile, value string) (int, error) {
	if value == "" || value == "unsharded" {
		return -1, nil
	}
	if profile == "windows11-x64-compat-arm64-v1" && len(value) == 1 && value[0] >= '0' && value[0] <= '2' {
		return int(value[0] - '0'), nil
	}
	return -1, errors.New("unsupported-corpus-shard")
}

// Assign by top-level NAME, not package: one global Go -run expression must
// never select an identically named test from another shard/package.
func corpusShardIndex(name string) int {
	sum := sha256.Sum256([]byte(name))
	return int(binary.BigEndian.Uint64(sum[:8]) % 3)
}

func corpusShardRequirements(index int) []string {
	if index < 0 {
		return requiredIntelligenceCases
	}
	var selected []string
	for _, key := range requiredIntelligenceCases {
		_, name, _ := strings.Cut(key, "#")
		if corpusShardIndex(name) == index {
			selected = append(selected, key)
		}
	}
	return selected
}

var corpusTestName = regexp.MustCompile(`^(Test|Example|Fuzz)[\pL\pN_]*$`)
var corpusPackage = regexp.MustCompile(`^packtrace(?:/[A-Za-z0-9_.-]+)*$`)

func corpusShardPattern(data []byte, index int) (string, []string, error) {
	bad := errors.New("invalid-corpus-inventory")
	if index < 0 || index > 2 || len(data) == 0 || len(data) > 4<<20 || data[len(data)-1] != '\n' {
		return "", nil, bad
	}
	packages := make(map[string]bool)
	ids, selected := make(map[string]bool), make(map[string]bool)
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var event struct{ Action, Package, Test, Output string }
		if json.Unmarshal(scan.Bytes(), &event) != nil || event.Test != "" || event.Action == "fail" || event.Action == "build-fail" {
			return "", nil, bad
		}
		if event.Action == "build-output" {
			continue
		}
		if len(event.Package) > 512 || !corpusPackage.MatchString(event.Package) || strings.Contains(event.Package, "/..") || strings.Contains(event.Package, "/./") || strings.HasSuffix(event.Package, "/.") {
			return "", nil, bad
		}
		finished, exists := packages[event.Package]
		switch event.Action {
		case "start":
			if exists {
				return "", nil, bad
			}
			packages[event.Package] = false
		case "pass", "skip":
			if !exists || finished {
				return "", nil, bad
			}
			packages[event.Package] = true
		case "output":
			if !exists || finished {
				return "", nil, bad
			}
			for _, name := range strings.Split(event.Output, "\n") {
				if !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Example") && !strings.HasPrefix(name, "Fuzz") {
					continue
				}
				id := event.Package + "#" + name
				if len(name) > 256 || !corpusTestName.MatchString(name) || ids[id] || len(ids) >= 10000 {
					return "", nil, bad
				}
				ids[id] = true
				if corpusShardIndex(name) == index {
					selected[name] = true
				}
			}
		default:
			return "", nil, bad
		}
	}
	if scan.Err() != nil || len(ids) == 0 || len(selected) == 0 {
		return "", nil, bad
	}
	for _, complete := range packages {
		if !complete {
			return "", nil, bad
		}
	}
	var inventory, names []string
	for id := range ids {
		inventory = append(inventory, id)
	}
	for name := range selected {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Strings(inventory)
	sort.Strings(names)
	pattern := "^(" + strings.Join(names, "|") + ")$"
	// ponytail: one <=16KiB regex stays below Windows argv; batch only if the inventory outgrows it.
	if len(pattern) > 16<<10 {
		return "", nil, errors.New("corpus-shard-argument-limit")
	}
	return pattern, inventory, nil
}
