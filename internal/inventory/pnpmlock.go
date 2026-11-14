package inventory

import (
	"bytes"
	"crypto/sha256"
	"io"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	maxPNPMBytes       = 1 << 20
	maxPNPMDepth       = 64
	maxPNPMNodes       = 100_000
	maxPNPMScalarBytes = 64 << 10
)

// PNPMLockDocument owns retained source nodes. Its public digest is evidence,
// not permission to inspect paths or authenticate any package origin.
type PNPMLockDocument struct {
	SHA256 [32]byte
	root   *yaml.Node
	digest [32]byte
	valid  bool
}

// ParsePNPMLock reads only format 9.0, without resolving or executing anything.
// Unknown fields remain uninterpreted source evidence. The caller must not
// mutate data concurrently. Returned storage does not borrow the caller's bytes.
func ParsePNPMLock(data []byte) (PNPMLockDocument, error) {
	if len(data) > maxPNPMBytes {
		return PNPMLockDocument{}, pnpmError("limit-exceeded")
	}
	if !utf8.Valid(data) {
		return PNPMLockDocument{}, pnpmError("invalid-yaml")
	}
	owned := bytes.Clone(data)
	decoder := yaml.NewDecoder(bytes.NewReader(owned))
	var node yaml.Node
	// Decode into nodes, never native maps: aliases are retained, not expanded.
	// v3.0.6 scannerc.go caps flow nesting/indentation at 10,000; the raw
	// ceiling bounds transient decoding work before our tighter node/depth pass.
	if err := decoder.Decode(&node); err != nil {
		return PNPMLockDocument{}, pnpmError("invalid-yaml")
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return PNPMLockDocument{}, pnpmError("invalid-shape")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return PNPMLockDocument{}, pnpmError("invalid-shape")
	}
	count := 1 // Include the document wrapper in the total node allowance.
	if err := pnpmValidateNode(node.Content[0], 1, &count, pnpmTagMarks(owned)); err != nil {
		return PNPMLockDocument{}, err
	}
	root := node.Content[0]
	version := pnpmLookup(root, "lockfileVersion")
	if version == nil || version.Kind != yaml.ScalarNode {
		return PNPMLockDocument{}, pnpmError("invalid-shape")
	}
	quoted := version.Tag == "!!str" && (version.Style == yaml.SingleQuotedStyle || version.Style == yaml.DoubleQuotedStyle)
	if version.Value != "9.0" || !(quoted || version.Tag == "!!float" && version.Style == 0) {
		return PNPMLockDocument{}, pnpmError("unsupported-version")
	}
	sum := sha256.Sum256(owned)
	doc := PNPMLockDocument{SHA256: sum, root: root, digest: sum, valid: true}
	// Structural typing and aggregate output bounds are also parse requirements.
	if _, err := ProjectPNPMLock(doc); err != nil {
		return PNPMLockDocument{}, err
	}
	return doc, nil
}

func pnpmError(code string) error { return &ParseError{Code: code} }

func pnpmValidateNode(n *yaml.Node, depth int, count *int, tags map[[2]int]bool) error {
	*count++
	if depth > maxPNPMDepth || *count > maxPNPMNodes || len(n.Value) > maxPNPMScalarBytes {
		return pnpmError("limit-exceeded")
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 || tags[[2]int{n.Line, n.Column}] {
		return pnpmError("invalid-shape")
	}
	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 {
			return pnpmError("invalid-shape")
		}
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return pnpmError("invalid-shape")
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode, yaml.ScalarNode:
	default:
		return pnpmError("invalid-shape")
	}
	for _, child := range n.Content {
		if err := pnpmValidateNode(child, depth+1, count, tags); err != nil {
			return err
		}
	}
	return nil
}

// yaml.v3 intentionally elides the nonspecific explicit tag "!" in Node.Style.
// Use its source marks to reject that spelling too, without lexing YAML ourselves.
// Bangs in ordinary scalar content/comments are not at a tagged node's mark.
func pnpmTagMarks(data []byte) map[[2]int]bool {
	marks := map[[2]int]bool{}
	line, column := 1, 1
	previousCR := false
	for i, r := range string(data) {
		if i == 0 && r == '\ufeff' {
			continue
		}
		if r == '!' {
			marks[[2]int{line, column}] = true
		}
		switch r {
		case '\r':
			line++
			column = 1
		case '\n':
			if !previousCR {
				line++
			}
			column = 1
		case '\u0085', '\u2028', '\u2029':
			line++
			column = 1
		default:
			column++
		}
		previousCR = r == '\r'
	}
	return marks
}

func pnpmLookup(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
