# Third-party notices

PackTrace's pnpm lockfile reader uses `go.yaml.in/yaml/v3` **v3.0.6**
([source](https://github.com/yaml/go-yaml/tree/v3.0.6), revision
`5a62aba63b773192cd10ab954e21e143d7b00c7a`). The dependency is vendored so
ordinary builds and scans do not need network access.

The ported libyaml files are licensed under MIT; the remaining project files are
licensed under Apache-2.0. These are licenses for different portions, not a choice
to relicense the whole dependency under either one. Original copyright/license
and attribution notices are preserved unchanged in:

- [`vendor/go.yaml.in/yaml/v3/LICENSE`](vendor/go.yaml.in/yaml/v3/LICENSE)
- [`vendor/go.yaml.in/yaml/v3/NOTICE`](vendor/go.yaml.in/yaml/v3/NOTICE)
- [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)

Distributions of binaries containing this dependency must retain the applicable
license texts and notices. Go/toolchain distribution notices and advisory dataset
licenses remain separate. This notice does not introduce a PackTrace project
license, include pnpm as a runtime dependency, authenticate inspected inputs, or
claim compatibility with every pnpm release or installed layout.
