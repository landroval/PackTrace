package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestCorpusShardSelectionKeepsUnshardedAndNativeProfilesClosed(t *testing.T) {
	for _, value := range []string{"", "unsharded"} {
		if index, e := corpusShardSelection("windows-scan-amd64-v1", value); e != nil || index != -1 {
			t.Fatal(index, e)
		}
	}
	for index := 0; index < 3; index++ {
		if actual, e := corpusShardSelection("windows11-x64-compat-arm64-v1", fmt.Sprint(index)); e != nil || actual != index {
			t.Fatal("closed emulated shard rejected", actual, e)
		}
	}
	for _, value := range []string{"all", "3", "-1", "01", "0|1", "0/.*"} {
		if _, e := corpusShardSelection("windows11-x64-compat-arm64-v1", value); e == nil {
			t.Fatal("unbounded selector accepted", value)
		}
	}
	if _, e := corpusShardSelection("windows-scan-amd64-v1", "0"); e == nil {
		t.Fatal("native profile changed into a subset")
	}
}

func TestCorpusShardPatternsAreDisjointExhaustiveAndKeepDuplicateNamesTogether(t *testing.T) {
	var data bytes.Buffer
	encode := json.NewEncoder(&data)
	for _, pkg := range []string{"packtrace/owned", "packtrace/other"} {
		encode.Encode(map[string]string{"Action": "start", "Package": pkg})
		for i := 0; i < 60; i++ {
			encode.Encode(map[string]string{"Action": "output", "Package": pkg, "Output": fmt.Sprintf("TestOwned%d\n", i)})
		}
		for _, name := range []string{"Example", "FuzzOwned", "TestÑame"} {
			encode.Encode(map[string]string{"Action": "output", "Package": pkg, "Output": name + "\n"})
		}
		encode.Encode(map[string]string{"Action": "pass", "Package": pkg})
	}
	var patterns []*regexp.Regexp
	for index := 0; index < 3; index++ {
		pattern, inventory, e := corpusShardPattern(data.Bytes(), index)
		if e != nil || len(inventory) != 126 || len(pattern) > 16<<10 {
			t.Fatal("full inventory/pattern not bounded", len(inventory), e)
		}
		patterns = append(patterns, regexp.MustCompile(pattern))
		for _, id := range inventory {
			name := strings.Split(id, "#")[1]
			if patterns[index].MatchString(name) != (corpusShardIndex(name) == index) {
				t.Fatal("global name selector crossed package/shard", id, index)
			}
		}
	}
	for i := 0; i < 60; i++ {
		matches := 0
		for _, p := range patterns {
			if p.MatchString(fmt.Sprintf("TestOwned%d", i)) {
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("omitted or overlapping test", i, matches)
		}
	}
	for _, bad := range [][]byte{nil, data.Bytes()[:data.Len()-1], append(append([]byte(nil), data.Bytes()...), []byte("{\"Action\":\"fail\",\"Package\":\"packtrace/owned\"}\n")...)} {
		if _, _, e := corpusShardPattern(bad, 0); e == nil {
			t.Fatal("incomplete/failed inventory supplied selection")
		}
	}
}
