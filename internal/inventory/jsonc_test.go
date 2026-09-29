package inventory

import (
	"strings"
	"testing"
)

func TestNormalizeJSONCAcceptsAndPreservesLength(t *testing.T) {
	cases := []struct {
		name  string
		build func() (input, want string)
	}{
		{
			name: "line comment before newline",
			build: func() (string, string) {
				prefix := `{"a":1,`
				comment := "// note"
				suffix := "\n\"b\":2}"
				return prefix + comment + suffix, prefix + strings.Repeat(" ", len(comment)) + suffix
			},
		},
		{
			name: "line comment at end of input with no newline",
			build: func() (string, string) {
				body := `{"a":1,"b":2}`
				comment := "// trailing, no newline"
				return body + comment, body + strings.Repeat(" ", len(comment))
			},
		},
		{
			name: "block comment mid document",
			build: func() (string, string) {
				prefix := `{"a":1`
				comment := "/* note */"
				suffix := `,"b":2}`
				return prefix + comment + suffix, prefix + strings.Repeat(" ", len(comment)) + suffix
			},
		},
		{
			name: "trailing comma in object",
			build: func() (string, string) {
				return `{"a":1,}`, `{"a":1 }`
			},
		},
		{
			name: "trailing comma in array",
			build: func() (string, string) {
				return `[1,2,]`, `[1,2 ]`
			},
		},
		{
			name: "trailing comma followed by whitespace then closer",
			build: func() (string, string) {
				prefix := "[1,2,"
				gap := "  \n "
				suffix := "]"
				want := prefix[:len(prefix)-1] + " " + gap + suffix
				return prefix + gap + suffix, want
			},
		},
		{
			name: "comment between trailing comma and closing bracket",
			build: func() (string, string) {
				prefix := "[1,2,"
				comment := "/* x */"
				suffix := "]"
				want := prefix[:len(prefix)-1] + " " + strings.Repeat(" ", len(comment)) + suffix
				return prefix + comment + suffix, want
			},
		},
		{
			name: "comment between trailing comma and closing brace",
			build: func() (string, string) {
				prefix := `{"a":1,`
				comment := "// note"
				suffix := "\n}"
				want := prefix[:len(prefix)-1] + " " + strings.Repeat(" ", len(comment)) + suffix
				return prefix + comment + suffix, want
			},
		},
		{
			name: "non-trailing comma stays a comma across a comment",
			build: func() (string, string) {
				prefix := `{"a":1,`
				comment := "/* not trailing */"
				suffix := `"b":2}`
				return prefix + comment + suffix, prefix + strings.Repeat(" ", len(comment)) + suffix
			},
		},
		{
			name: "CRLF around a line comment",
			build: func() (string, string) {
				comment := "// note"
				input := "{\"a\":1" + comment + "\r\n}"
				want := "{\"a\":1" + strings.Repeat(" ", len(comment)) + "\r\n}"
				return input, want
			},
		},
		{
			name: "string content is never altered",
			build: func() (string, string) {
				body := `{"a":"http://example.com","b":"/* not a comment */","c":"trailing,}","d":"quote\"inside","e":"back\\slash"}`
				return body, body
			},
		},
		{
			name: "empty object and array bodies are untouched",
			build: func() (string, string) {
				return `{"a":{},"b":[]}`, `{"a":{},"b":[]}`
			},
		},
		{
			name: "escaped backslash before a closing quote ends the string",
			build: func() (string, string) {
				return `{"a":"x\\", /* c */ "b":1,}`, `{"a":"x\\",         "b":1 }`
			},
		},
		{
			name: "escaped quote does not end a string before comment-like bytes",
			build: func() (string, string) {
				return `{"a":"q\"/*x*/,}","b":1}`, `{"a":"q\"/*x*/,}","b":1}`
			},
		},
		{
			name: "block comment opener is never its own closer",
			build: func() (string, string) {
				return `{"a":1 /*/ "hidden":2 /*/}`, `{"a":1                   }`
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, want := tc.build()
			out, ok := normalizeJSONC([]byte(input))
			if !ok {
				t.Fatalf("normalizeJSONC rejected an accepted input: %q", input)
			}
			if len(out) != len(input) {
				t.Fatalf("normalized length changed: got %d, want %d", len(out), len(input))
			}
			if string(out) != want {
				t.Fatalf("normalized mismatch:\ngot:  %q\nwant: %q", out, want)
			}
		})
	}
}

func TestNormalizeJSONCPreservesLineBreakPositions(t *testing.T) {
	input := "{\n\"a\":1, // c\r\n\"b\":/* x\ny */2,\n}"
	out, ok := normalizeJSONC([]byte(input))
	if !ok {
		t.Fatal("expected acceptance of a document mixing comments, CRLF, and a trailing comma")
	}
	if len(out) != len(input) {
		t.Fatalf("length changed: got %d, want %d", len(out), len(input))
	}
	for i := range input {
		b := input[i]
		if b != '\n' && b != '\r' {
			continue
		}
		if out[i] != b {
			t.Fatalf("byte %d: line break changed: got %q, want %q", i, out[i], b)
		}
	}
}

func TestNormalizeJSONCRejects(t *testing.T) {
	cases := []struct{ name, input string }{
		{"leading comma in object", `{,}`},
		{"leading comma in array", `[,]`},
		{"double comma in array", `[1,,]`},
		{"leading comma before a value", `[,1]`},
		{"double comma in object", `{"a":1,,}`},
		{"comma directly after colon", `{"a":,}`},
		{"comma at start of input", `,`},
		{"unterminated block comment", `/* open`},
		{"unterminated block comment with content", `{"a":1} /* open forever`},
		{"block comment opener alone", `{"a":1} /*/`},
		{"lone slash", `/`},
		{"lone slash inside document", `{"a":1} / "b"`},
		{"slash followed by unrelated byte", `/x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := normalizeJSONC([]byte(tc.input)); ok {
				t.Fatalf("normalizeJSONC accepted invalid JSONC syntax: %q", tc.input)
			}
		})
	}
}
