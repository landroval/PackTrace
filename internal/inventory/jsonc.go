package inventory

// normalizeJSONC blanks comments and trailing commas with spaces, preserving length
// and line breaks. It is not syntax validation; jsoninput validates the result.
// It rejects unterminated comments, stray slashes, and commas without a value.
func normalizeJSONC(data []byte) ([]byte, bool) {
	out := append([]byte(nil), data...)

	precededByValue := false
	pendingComma := -1

	for i := 0; i < len(out); {
		b := out[i]
		if b == '/' {
			next, ok := blankComment(out, i)
			if !ok {
				return nil, false
			}
			i = next
			continue
		}
		if b == '"' {
			resolvePendingComma(out, &pendingComma, false)
			precededByValue = true
			i = skipString(out, i)
			continue
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			i++
		case ',':
			if !precededByValue {
				return nil, false
			}
			pendingComma = i
			precededByValue = false
			i++
		case '}', ']':
			resolvePendingComma(out, &pendingComma, true)
			precededByValue = true
			i++
		case '{', '[', ':':
			resolvePendingComma(out, &pendingComma, false)
			precededByValue = false
			i++
		default:
			resolvePendingComma(out, &pendingComma, false)
			precededByValue = true
			i++
		}
	}
	return out, true
}

// blankComment blanks the comment starting at data[start] or rejects a stray slash.
func blankComment(data []byte, start int) (int, bool) {
	hasNext := start+1 < len(data)
	switch {
	case hasNext && data[start+1] == '/':
		return blankLineComment(data, start), true
	case hasNext && data[start+1] == '*':
		return blankBlockComment(data, start)
	default:
		return 0, false
	}
}

// resolvePendingComma blanks a pending comma only before a closing bracket; any
// other significant byte keeps it as a separator.
func resolvePendingComma(out []byte, pendingComma *int, closing bool) {
	if *pendingComma < 0 {
		return
	}
	if closing {
		out[*pendingComma] = ' '
	}
	*pendingComma = -1
}

// skipString returns the index after a string without changing its bytes. An
// unterminated string is left for jsoninput to reject.
func skipString(data []byte, start int) int {
	i := start + 1
	for i < len(data) {
		switch data[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return i
}

// blankLineComment blanks a `//` comment up to, not including, its line break.
func blankLineComment(data []byte, start int) int {
	i := start
	for i < len(data) && data[i] != '\n' && data[i] != '\r' {
		data[i] = ' '
		i++
	}
	return i
}

// blankBlockComment blanks a `/* */` comment except line breaks, searching after the
// opener so `/*/` never closes itself. It reports false when unterminated.
func blankBlockComment(data []byte, start int) (int, bool) {
	data[start] = ' '
	data[start+1] = ' '
	i := start + 2
	for i < len(data) {
		if data[i] == '*' && i+1 < len(data) && data[i+1] == '/' {
			data[i] = ' '
			data[i+1] = ' '
			return i + 2, true
		}
		if data[i] != '\n' && data[i] != '\r' {
			data[i] = ' '
		}
		i++
	}
	return i, false
}
