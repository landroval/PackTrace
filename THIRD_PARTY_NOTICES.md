# Third-party Go software

PackTrace's optional interactive terminal view uses these pinned direct libraries:

| Module | Version | License |
| --- | --- | --- |
| `charm.land/bubbletea/v2` | `v2.1.1` | MIT |
| `charm.land/bubbles/v2` | `v2.2.1` | MIT |
| `charm.land/lipgloss/v2` | `v2.0.6` | MIT |
| `github.com/charmbracelet/colorprofile` | `v0.4.3` | MIT |
| `github.com/charmbracelet/x/term` | `v0.2.2` | MIT |
| `github.com/charmbracelet/ultraviolet` | `v0.0.0-20261008173134-6b8d4baf91b4` | MIT |
| `golang.org/x/sys` | `v0.47.0` | BSD-3-Clause |

The module graph and checksums are recorded in [go.mod](go.mod) and [go.sum](go.sum).
Runtime source is vendored so ordinary builds and root CI remain offline. Exact
vendored versions, including transitive modules, are in
[vendor/modules.txt](vendor/modules.txt); their full copyright and license files
are retained with each module under [vendor/](vendor/). Include those notices
when distributing the corresponding software. Transitive software uses
its own MIT/BSD-style or other included notices; do not treat the three direct
MIT grants as a license for every dependency or for advisory datasets.

The UI imports only the components it uses. It has no clipboard, shell-command,
editor, browser, SSH or artifact-download action. Dependencies being present in
the module graph does not authorize invoking unrelated features.

Advisory data licensing is separate: see the
[data-source notices](internal/intelstore/licenses/README.md). Module checksums
and source transport verification do not authenticate an advisory publisher or
establish the safety of an investigated package.
