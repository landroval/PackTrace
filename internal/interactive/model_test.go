package interactive

import (
	tea "charm.land/bubbletea/v2"
	"packtrace/internal/cli"
	"strings"
	"testing"
)

func TestViewerFiltersWithoutChangingEvidenceOrExit(t *testing.T) {
	data := cli.InteractiveView{Summary: "Required coverage: incomplete\nComparison exit: 3", Exit: 3, Rows: []cli.InteractiveRow{{Name: "alpha", Version: "1.0.0", State: "REVIEW", Details: "Unconfirmed origin"}, {Name: "beta", Version: "2.0.0", State: "FINDING", Details: "Not proof of execution"}}}
	m := New(data, 100, 30)
	send := func(k tea.KeyPressMsg) { v, _ := m.Update(k); m = v.(Model) }
	send(tea.KeyPressMsg{Code: '/'})
	for _, r := range "beta" {
		send(tea.KeyPressMsg{Code: r})
	}
	send(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.indices) != 1 || m.Data.Exit != 3 || len(m.Data.Rows) != 2 {
		t.Fatal("filter changed evidence or failed", m.Query, m.indices)
	}
	send(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !strings.Contains(m.View().Content, "Not proof of execution") {
		t.Fatal("missing selected detail")
	}
	send(tea.KeyPressMsg{Code: 's'})
	if !strings.Contains(m.View().Content, "Required coverage") {
		t.Fatal("summary hidden")
	}
	send(tea.KeyPressMsg{Code: '?'})
	if !strings.Contains(m.View().Content, "read-only") && !strings.Contains(m.View().Content, "Read-only") {
		t.Fatal("help missing")
	}
	send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !m.Interrupted {
		t.Fatal("Ctrl+C lost interruption")
	}
	if m.View().AltScreen || m.View().MouseMode != tea.MouseModeNone || m.View().Cursor == nil {
		t.Fatal("unnecessary terminal modes enabled")
	}
}
