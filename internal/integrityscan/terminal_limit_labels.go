package integrityscan

import "strings"

// Translate known scope markers, never infer missing severity or applicability.
func terminalLimitLabel(code string) string {
	switch code {
	case "declared-unassessed":
		return "declared requirements not assessed"
	case "index-completeness":
		return "exhaustive advisory coverage unverified"
	case "source-check-expired":
		return "advisory source check expired"
	case "source-check-unknown":
		return "advisory source check age unknown"
	case "full-reconciliation-expired":
		return "full reconciliation expired"
	case "full-reconciliation-unknown":
		return "full reconciliation age unknown"
	case "identity-byte-limit":
		return "advisory read byte limit reached"
	case "evaluation-limit":
		return "advisory evaluation limit reached"
	case "observation-limit":
		return "observation limit reached"
	default:
		return strings.ReplaceAll(code, "-", " ")
	}
}
