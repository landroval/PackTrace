// Package interactive displays only a bounded parent-approved view. It has no
// target/store/policy access and cannot select the scan's public exit code.
package interactive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/term"
	"packtrace/internal/cli"
)

type Model struct {
	Data                                        cli.InteractiveView
	Table                                       table.Model
	Detail                                      viewport.Model
	indices                                     []int
	Query                                       string
	Search, Details, Summary, Help, Interrupted bool
	Width, Height                               int
}

func New(v cli.InteractiveView, w, h int) Model {
	m := Model{Data: v, Table: table.New(table.WithFocused(true)), Detail: viewport.New(), Summary: true}
	m.resize(w, h)
	m.filter()
	return m
}
func (m *Model) resize(w, h int) {
	m.Width = max(40, min(w, 180))
	m.Height = max(12, min(h, 60))
	left := max(20, m.Width/3)
	m.Table.SetColumns([]table.Column{{Title: "Package", Width: max(8, left-20)}, {Title: "Version", Width: 10}, {Title: "State", Width: 7}})
	m.Table.SetWidth(left)
	m.Table.SetHeight(m.Height - 7)
	m.Detail.SetWidth(max(15, m.Width-left-4))
	m.Detail.SetHeight(m.Height - 7)
}
func (m *Model) filter() {
	rows := []table.Row{}
	m.indices = nil
	for i, r := range m.Data.Rows {
		if strings.Contains(strings.ToLower(r.Name), strings.ToLower(m.Query)) {
			m.indices = append(m.indices, i)
			rows = append(rows, table.Row{r.Name, r.Version, r.State})
		}
	}
	m.Table.SetRows(rows)
	m.Table.SetCursor(0)
	m.content()
}
func (m *Model) content() {
	text := m.Data.Summary
	if m.Help {
		text = "Read-only result explorer\n\nq: close (keeps original comparison exit)\nCtrl+C: interrupt (130)\n/: search package names, Enter: finish search, Esc: clear\nTab: focus package list/details\ns: summary, Enter: selected package\n?: help\n\nFindings met rules, not proof of execution.\nCandidates are version leads, not confirmed vulnerabilities.\nCoverage gaps and PackTrace validation stay in Summary.\nFilters never remove evidence or waive coverage.\nNo downloads, dependency changes, file opens or clipboard access.\nThe same operation deadline still applies."
	} else if !m.Summary && len(m.indices) > 0 {
		i := m.Table.Cursor()
		if i >= 0 && i < len(m.indices) {
			text = m.Data.Rows[m.indices[i]].Details
		}
	}
	m.Detail.SetContent(text)
}
func (m Model) Init() tea.Cmd { return nil }
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(v.Width, v.Height)
		m.content()
	case tea.KeyPressMsg:
		k := v.String()
		if k == "ctrl+c" {
			m.Interrupted = true
			return m, tea.Quit
		}
		if m.Search {
			switch k {
			case "enter":
				m.Search = false
			case "esc":
				m.Search = false
				m.Query = ""
			case "backspace":
				if len(m.Query) > 0 {
					m.Query = m.Query[:len(m.Query)-1]
				}
			default:
				if len(k) == 1 && k[0] >= 32 && k[0] < 127 && len(m.Query) < 64 {
					m.Query += k
				}
			}
			m.filter()
			return m, nil
		}
		switch k {
		case "q", "esc":
			return m, tea.Quit
		case "/":
			m.Search = true
			return m, nil
		case "?":
			m.Help = !m.Help
			m.content()
			return m, nil
		case "s":
			m.Summary = true
			m.Help = false
			m.content()
			return m, nil
		case "tab":
			m.Details = !m.Details
			return m, nil
		case "enter":
			m.Summary = false
			m.Help = false
			m.content()
			return m, nil
		}
		if m.Details {
			var cmd tea.Cmd
			m.Detail, cmd = m.Detail.Update(msg)
			return m, cmd
		}
		var cmd tea.Cmd
		m.Table, cmd = m.Table.Update(msg)
		m.Summary = false
		m.Help = false
		m.content()
		return m, cmd
	}
	return m, nil
}
func (m Model) View() tea.View {
	title := fmt.Sprintf("PackTrace | read-only results | comparison exit %d | rows %d/%d", m.Data.Exit, len(m.indices), len(m.Data.Rows))
	footer := "up/down select | Enter details | Tab focus | / search | s summary | ? help | q close | Ctrl+C interrupt"
	if m.Search {
		footer = "Search: " + m.Query + " | Enter finish | Esc clear"
	}
	v := tea.NewView(title + "\n" + lipgloss.JoinHorizontal(lipgloss.Top, m.Table.View(), "  ", m.Detail.View()) + "\n" + footer)
	// No alternate-screen/mouse/paste/terminal-title state: a killed observed
	// writer must not strand those modes. The parent restores original termios.
	v.Cursor = tea.NewCursor(0, m.Height-1)
	v.DisableBracketedPasteMode = true
	return v
}

type boundedOutput struct {
	file  *os.File
	mu    sync.Mutex
	n     int
	limit int
}

func (w *boundedOutput) Fd() uintptr              { return w.file.Fd() }
func (w *boundedOutput) Read([]byte) (int, error) { return 0, errors.New("output-only terminal") }
func (w *boundedOutput) Close() error             { return nil }
func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) > w.limit-w.n {
		return 0, errors.New("interactive output limit")
	}
	n, e := w.file.Write(p)
	w.n += n
	return n, e
}
func Run(in, out *os.File, v cli.InteractiveView, width, height int, color bool, ms, limit int) (bool, int, error) {
	if cli.ValidateInteractiveView(v) != nil || ms < 1 || ms > 900000 || limit < 1 {
		return false, 0, errors.New("invalid interactive request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
	defer cancel()
	sink := &boundedOutput{file: out, limit: limit}
	profile := colorprofile.ASCII
	if color {
		profile = colorprofile.ANSI256
	}
	// Disable Bubble Tea's automatic terminal queries and enhanced keyboard
	// modes. Feed parsed keys explicitly; only temporary kernel input mode is
	// changed, and the supervising parent also restores it after forced reap.
	old, e := term.MakeRaw(in.Fd())
	if e != nil {
		return false, 0, e
	}
	defer term.Restore(in.Fd(), old)
	p := tea.NewProgram(New(v, width, height), tea.WithInput(nil), tea.WithOutput(sink), tea.WithContext(ctx), tea.WithWindowSize(width, height), tea.WithColorProfile(profile), tea.WithEnvironment([]string{"TERM=xterm-256color", "HOME="}), tea.WithFPS(15), tea.WithoutSignalHandler())
	readCtx, stopRead := context.WithCancel(ctx)
	defer stopRead()
	reader, e := uv.NewCancelReader(in)
	if e != nil {
		return false, sink.n, e
	}
	defer reader.Close()
	events := make(chan uv.Event, 32)
	readDone := make(chan error, 1)
	pumpDone := make(chan struct{})
	go func() {
		e := uv.NewTerminalReader(reader, "xterm-256color").StreamEvents(readCtx, events)
		close(events)
		readDone <- e
	}()
	go func() {
		defer close(pumpDone)
		for event := range events {
			if key, ok := event.(uv.KeyPressEvent); ok {
				p.Send(tea.KeyPressMsg(key))
			}
		}
		// Unexpected input termination is an output operation failure, not a
		// successful close. After normal quit Send simply observes the closed run.
		p.Send(tea.InterruptMsg{})
	}()
	last, err := p.Run()
	stopRead()
	reader.Cancel()
	readErr := <-readDone
	<-pumpDone
	if err == nil {
		err = readErr
	}
	m, ok := last.(Model)
	if !ok {
		return false, sink.n, errors.New("invalid interactive completion")
	}
	return m.Interrupted, sink.n, err
}
