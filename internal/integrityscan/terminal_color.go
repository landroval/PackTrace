package integrityscan

import "strings"

// Styles follow explicit state labels, never inferred severity or zero-result
// counts. Apply only after escaping/alignment; stripping SGR recovers plain text.
func colorTerminalSummary(data []byte) []byte {
	var out strings.Builder
	for _, line := range strings.SplitAfter(string(data), "\n") {
		body := strings.TrimSuffix(line, "\n")
		label := strings.TrimLeft(body, " ")
		style := ""
		switch {
		case strings.HasPrefix(label, "[OK]"):
			style = "\x1b[1;32m"
		case strings.HasPrefix(label, "[FINDING]"), strings.HasPrefix(label, "[ERROR]"):
			style = "\x1b[1;31m"
		case strings.HasPrefix(label, "[REVIEW]"):
			style = "\x1b[1;35m"
		case strings.HasPrefix(label, "[INCOMPLETE]"):
			style = "\x1b[1;33m"
		case strings.HasPrefix(label, "[NOT RUN]"):
			style = "\x1b[37m" // Light gray, not low-contrast dim text.
		case strings.HasPrefix(label, "[INFO]"):
			style = "\x1b[36m"
		case strings.HasPrefix(body, "PackTrace |"), body == "Summary", body == "Packages to review", body == "Coverage limitations", body == "Check status", strings.HasPrefix(body, "PACKAGE "):
			style = "\x1b[1;34m"
		}
		if style != "" {
			out.WriteString(style)
			out.WriteString(body)
			out.WriteString("\x1b[0m")
		} else {
			out.WriteString(body)
		}
		if strings.HasSuffix(line, "\n") {
			out.WriteByte('\n')
		}
	}
	return []byte(out.String())
}
