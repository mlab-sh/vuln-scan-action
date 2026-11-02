# vuln.mlab.sh SBOM scan: GitHub Action

Scan your lockfiles and SBOMs for known CVEs on every push or pull request,
powered by [vuln.mlab.sh](https://vuln.mlab.sh).

- **Scan**: auto-detects lockfiles, checks every dependency against OSV and NVD,
  annotates the vulnerable lines in the pull request, writes a job summary.
- **Gate**: `block` / `warn` rules on severity, real exploitation (CISA / EU KEV,
  EPSS, threat actors), a score, or coverage. Or a plain `fail-on` threshold.
- **Report**: SARIF upload to GitHub Code Scanning, a score badge for your README,
  a signed attestation of the scan (Sigstore) bound to your release artifact.
- **Monitor**: register your lockfiles on vuln.mlab.sh to be alerted on CVEs
  published after the build.

No dependency install, no local database: parsing and scanning happen server
side. The Action uploads your lockfile and reports the result.

## Contents

- [Quick start](#quick-start)
- [Token and limits](#token-and-limits)
- [Examples](#examples)
- [Configuration file: `.mlab/vuln.yml`](#configuration-file-mlabvulnyml)
- [Gate rules](#gate-rules)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Permissions](#permissions)
- [Features](#features): [Code Scanning](#github-code-scanning), [badge](#score-badge), [monitoring](#continuous-monitoring), [attestation](#signed-attestation)
- [How it works](#how-it-works)

## Quick start

```yaml
# .github/workflows/sbom.yml
name: SBOM scan
on: [push, pull_request]

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlab-sh/vuln-scan-action@v1
        with:
          fail-on: high
          token: ${{ secrets.VULN_MLAB_TOKEN }}
```

With no inputs, it auto-detects the supported lockfiles in the repo and fails on
**any** known vulnerability.

## Token and limits

| | Packages per lockfile | Request size | Cooldown between scans |
| --- | --- | --- | --- |
| Anonymous (per IP) | 512 | 4 MiB | 10 s |
| Free account, with a token | 1024 | 8 MiB | 5 s |
| Paid plan, with a token | 4096 | 32 MiB | none |

GitHub-hosted runners share egress IPs across many repositories, so an anonymous
cooldown can be taken by someone else's job. The Action waits out the cooldown
the server announces and retries, but a token is faster and steadier, and its
scans land in your history on vuln.mlab.sh. Monitoring needs one.

1. Sign in at [vuln.mlab.sh/me/tokens](https://vuln.mlab.sh/me/tokens) and generate a token.
2. Add it as a repository (or organization) secret named `VULN_MLAB_TOKEN`.
3. Pass it via the `token:` input.

## Examples

Ready to copy, in [`examples/`](examples/).

**Workflows** (copy to `.github/workflows/`):

| File | What it does |
| --- | --- |
| [`basic.yml`](examples/workflows/basic.yml) | Push and PR scan, fail on high or critical. |
| [`report-only.yml`](examples/workflows/report-only.yml) | Never fail; read the outputs and decide yourself. |
| [`monorepo.yml`](examples/workflows/monorepo.yml) | Several lockfiles in one job, or one service by `working-directory`. |
| [`code-scanning.yml`](examples/workflows/code-scanning.yml) | Findings as alerts in the Security tab, plus a weekly rescan. |
| [`badge.yml`](examples/workflows/badge.yml) | Keep a score badge committed in the repo. |
| [`monitor.yml`](examples/workflows/monitor.yml) | Register the lockfiles for continuous monitoring on vuln.mlab.sh. |
| [`attest.yml`](examples/workflows/attest.yml) | Release: sign the scan and bind it to the artifact. |
| [`complete.yml`](examples/workflows/complete.yml) | All of it: PR gate, Code Scanning, monitoring and badge on main, weekly rescan. |

**`.mlab/vuln.yml`** (copy to `.mlab/vuln.yml` at the repository root):

| File | Policy |
| --- | --- |
| [`severity-gate.yml`](examples/vuln-yml/severity-gate.yml) | Block high and critical, warn on the rest, an ignore list. |
| [`exploit-first.yml`](examples/vuln-yml/exploit-first.yml) | Block what is exploited (KEV, EPSS, actors), warn on severity alone. |
| [`strict.yml`](examples/vuln-yml/strict.yml) | Production: block from medium, KEV, a score under 80, any coverage gap. |
| [`notify.yml`](examples/vuln-yml/notify.yml) | Rolling out: every rule reported, none fails. |
| [`disabled.yml`](examples/vuln-yml/disabled.yml) | Skip the scan in this repository. |

## Configuration file: `.mlab/vuln.yml`

Optional. The Action reads the same per repo file as the
[mlab VS Code extension](https://github.com/mlab-sh/vuln-scan-vscode), from the
repository root, so one file drives both the editor and CI.

| Key | Value | Effect |
| --- | --- | --- |
| `disable` | `true` | Skip the scan entirely: nothing is scanned, the job passes. |
| `ignoreVulns` | list of ids | Advisories accepted as known risk (CVE, GHSA, RUSTSEC, ...): not reported, never fail. Matched against the advisory id and all its aliases. |
| `block` | list of [rules](#gate-rules) | A rule that fires fails the check. |
| `warn` | list of [rules](#gate-rules) | A rule that fires is reported (warning, job summary), never fails. |
| `mode` | `gate` (default) or `notify` | `notify` never fails the check, like the `soft-fail` input. |

```yaml
mode: gate
block:
  - severity>=high
  - kev
warn:
  - severity>=medium
  - incomplete
ignoreVulns:
  - CVE-2024-0000   # not reachable: only used in tests
```

Other keys are editor settings and are ignored by the Action. The parser takes
flat `key: value` lines and lists (`- item` or `[a, b]`), with comments.

## Gate rules

| Rule | Fires when |
| --- | --- |
| `severity>=<any\|low\|medium\|high\|critical>` | a finding is at or above that severity (`any` includes unknown severity) |
| `kev` | a finding's CVE is in CISA KEV or the EU KEV: exploited in the wild |
| `epss>=<0..1>` | a finding's EPSS (probability of exploitation in the next 30 days) is at least that, e.g. `epss>=0.1` |
| `actor` | a threat actor is documented exploiting a finding's CVE ([actors.mlab.sh](https://actors.mlab.sh)) |
| `score<<0..100>` | the run's [score](#outputs) is below that, e.g. `score<70` |
| `unscanned` | a lockfile could not be scanned at all (too large, unreachable server) |
| `incomplete` | some package of a scanned lockfile was not checked (package limit, git or path dependency, unpinned version, outage) |

- **Which rules apply.** When `.mlab/vuln.yml` has a `block:` or `warn:` list,
  those rules replace the `fail-on` and `fail-on-incomplete` inputs. Without
  lists, the inputs build them: `fail-on: high` is `block: [severity>=high]`,
  `fail-on-incomplete: true` adds `incomplete`.
- **`unscanned` blocks by default**, unless one of the lists names it.
- **A typo fails the run** (`Unknown gate rule`) rather than leaving the gate open.
- **Exploitation data.** `kev`, `epss` and `actor` look each CVE up on the public
  [vuln.mlab.sh CVE API](https://vuln.mlab.sh/api) and actors.mlab.sh, only when
  a rule needs it: only the CVE id is sent, no quota. A CVE that could not be
  looked up is reported as a warning and does not match. The job summary then
  shows KEV, EPSS and actors next to each finding.
- **Fired rules** are listed in a *Gate* section of the job summary; `warn` rules
  also as warnings in the log.

## Inputs

All optional.

**Scan**

| Input | Default | Description |
| --- | --- | --- |
| `path` | *(auto-detect)* | Lockfile(s) or SBOM(s) to scan, newline- or comma-separated, relative to `working-directory`. |
| `working-directory` | `.` | Base directory for `path` and auto-detection. |
| `format` | `auto` | Force the parser: `npm`, `yarn`, `pnpm`, `cargo`, `pip`, `poetry`, `uv`, `pdm`, `pipfile`, `composer`, `gem`, `go`, `maven`, `nuget`, `pub`, `hex`, `mise`, `cyclonedx`, `spdx`. |
| `token` | *(none)* | vuln.mlab.sh API token. Strongly recommended in CI, required for `monitor`. |
| `api-url` | `https://vuln.mlab.sh/api/v2/scan` | Scan endpoint. Its origin is also used for CVE lookups and monitoring. |

**Gate**

| Input | Default | Description |
| --- | --- | --- |
| `fail-on` | `any` | Minimum severity that fails the build: `any`, `critical`, `high`, `medium`, `low`, `none`. Ignored when `.mlab/vuln.yml` has gate rules. |
| `fail-on-incomplete` | `false` | If `true`, also fail when some package was not scanned. Ignored when `.mlab/vuln.yml` has gate rules. |
| `soft-fail` | `false` | If `true`, never fail the build: report, set the outputs (`failed` included). |

**Reports and integrations**

| Input | Default | Description |
| --- | --- | --- |
| `sarif-file` | *(none)* | Write the findings as SARIF 2.1.0 to this path. |
| `upload-sarif` | `false` | If `true`, upload the SARIF to GitHub Code Scanning (a temp file when `sarif-file` is empty). |
| `github-token` | `${{ github.token }}` | Token for the GitHub API (SARIF upload). |
| `badge-file` | *(none)* | Write an SVG badge with the score to this path. Commit it in a later step. |
| `monitor` | `false` | If `true`, on a push to the default branch, register the lockfiles for continuous monitoring on vuln.mlab.sh (Pro plan). |
| `monitor-source-token` | *(none)* | Private repository only: a read-only token mlab uses to fetch the lockfiles on each rescan. |
| `attestation-predicate` | *(none)* | Write the scan as an in-toto vulnerability predicate to this path, for `actions/attest`. |

**Auto-detected lockfiles:** `Cargo.lock`, `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`,
`Gemfile.lock`, `go.sum`, `requirements.txt`, `poetry.lock`, `uv.lock`,
`pdm.lock`, `Pipfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`,
`pubspec.lock`, `mix.lock`, `mise.lock`, and CycloneDX SBOMs named `bom.json` or
`bom.xml`. (`node_modules`, `vendor`, `target`, dot-directories … are skipped.)
Any other SBOM (SPDX, a differently named CycloneDX file) can be passed in
`path`; components without a purl are matched by their CPE.

## Outputs

| Output | Description |
| --- | --- |
| `total` | Vulnerabilities found across all lockfiles, one per package and CVE. |
| `vulnerable-packages` | Number of distinct vulnerable packages. |
| `critical`, `high`, `medium`, `low`, `unknown` | Findings per severity. |
| `score` | 0 to 100: 100 with no finding, minus 20 a critical, 10 a high, 4 a medium, 1 a low, 2 an unknown, and 20 more for a CVE in KEV (when a `kev`, `epss` or `actor` rule looked it up). |
| `incomplete` | `true` if some package was not scanned (limit, unscannable entry, outage, or a lockfile that failed). |
| `not-scanned` | Packages left out because a manifest exceeded the package limit. |
| `failed` | `true` if a `block` rule fired, regardless of `soft-fail`. |
| `sarif-file` | Path of the SARIF file written, when one was. |
| `attestation-predicate` | Path of the attestation predicate written, when one was. |
| `attestation-predicate-type` | `https://in-toto.io/attestation/vulns/v0.1`, to pass to `actions/attest`. |

## Permissions

The scan itself needs only `contents: read`. Each integration adds:

| Feature | Inputs | `permissions:` | Secrets |
| --- | --- | --- | --- |
| Scan and gate | | `contents: read` | `VULN_MLAB_TOKEN` (recommended) |
| Code Scanning | `upload-sarif` | `security-events: write` | |
| Badge, committed by the workflow | `badge-file` | `contents: write` | |
| Monitoring | `monitor` | | `VULN_MLAB_TOKEN` on a Pro plan; a read-only repo token in `monitor-source-token` for a private repo |
| Attestation | `attestation-predicate` + `actions/attest` | `id-token: write`, `attestations: write` | |

Pull requests from forks get a read-only `GITHUB_TOKEN` and no secrets: the scan
runs anonymously and a SARIF upload is refused (a warning, not a failure).

## Features

### GitHub Code Scanning

`upload-sarif: true` puts each finding in the Security tab as an alert on the
lockfile line that declares the package, ranked by severity (`security-severity`);
alerts close when the dependency is upgraded. On a private repository code
scanning needs GitHub Advanced Security. A refused upload is a warning, not a
failed scan. To upload with `github/codeql-action/upload-sarif` instead, set
`sarif-file` and pass that path to it.
Example: [`code-scanning.yml`](examples/workflows/code-scanning.yml).

### Score badge

`badge-file` writes a shields-style SVG with the [score](#outputs) (`92/100`,
green to red), or a grey `incomplete` when the scan did not cover every package.
The Action only writes the file; a later step commits it
([`badge.yml`](examples/workflows/badge.yml)). Then, in your README:

```markdown
![vulnerabilities](.github/badges/vulns.svg)
```

Lockfiles monitored on vuln.mlab.sh can also have a server-side badge
(`/badge/sbom/<key>.svg`) that follows the rescans.

### Continuous monitoring

A scan in CI only sees CVEs published before the build. With `monitor: true`, a
push to the default branch registers each scanned lockfile as a monitored
project on [vuln.mlab.sh/me/sbom](https://vuln.mlab.sh/me/sbom): mlab refetches
it from the branch tip (`raw.githubusercontent.com`), rescans it on schedule and
alerts you when a new CVE lands on a dependency you already ship. A lockfile
already monitored gets a rescan, not a duplicate. Other events (pull requests,
other branches) skip this step.

Monitoring is a Pro feature. A refusal (plan, project limit, invalid token) is a
warning and never fails the build. For a private repository, set
`monitor-source-token` to a fine-grained token with `contents: read` on the
repository; mlab stores it to fetch the lockfiles. Not `GITHUB_TOKEN`: it expires
with the job. Example: [`monitor.yml`](examples/workflows/monitor.yml).

### Signed attestation

`attestation-predicate` writes the scan as an
[in-toto vulnerability predicate](https://github.com/in-toto/attestation/tree/main/spec/predicates)
(`vulns/v0.1`): each CVE with its severity, package, lockfile, fixed version and
KEV status. [GitHub Artifact Attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
(`actions/attest`) sign it with Sigstore and bind it to your artifact and the
commit, next to its build provenance. Verify with:

```bash
gh attestation verify dist/app.tar.gz --repo <owner>/<repo> --predicate-type https://in-toto.io/attestation/vulns/v0.1
```

A gate that fails stops the job before the attestation; use `soft-fail` to
attest a failing scan too. Example: [`attest.yml`](examples/workflows/attest.yml).

## How it works

Each lockfile is POSTed to [`/api/v2/scan`](https://vuln.mlab.sh/api). The service
parses it, resolves every dependency's known vulnerabilities, and returns one
result per package. The Action then:

- merges the advisories that describe the same CVE (GHSA + RUSTSEC …) into one
  finding per package, keeping the worst severity,
- scores CVSS vectors when an advisory has no severity label,
- drops the advisories in `ignoreVulns`,
- looks up KEV, EPSS and actors when a gate rule needs them,
- annotates the worst offenders (up to 50) on the line of the lockfile that
  declares them (errors for high/critical, warnings otherwise),
- writes the SARIF, badge and attestation predicate you asked for, uploads the
  SARIF, registers the lockfiles for monitoring,
- writes the job summary: coverage per lockfile, fired rules, findings with
  their exploitation data and the version that fixes them,
- evaluates the gate rules, sets the outputs, and fails the check if a `block`
  rule fired (unless `soft-fail` or `mode: notify`).

## Notes

- Packages the scan did not cover are never counted as clean: a manifest over
  your package limit, entries the server cannot scan (git or path dependencies,
  unpinned versions, SBOM components with neither purl nor CPE), and packages
  left unchecked during an outage are listed as warnings and in the summary. Add
  `incomplete` to `block` (or `fail-on-incomplete: true`) to fail on them.
- A lockfile that cannot be scanned at all fails the gate (`unscanned`) after
  the other lockfiles are scanned and reported.
- Between lockfiles the Action waits out the cooldown the server announces, and
  on a 429 waits and retries; network errors and 5xx are retried with backoff.
- Pin `@v1` to follow compatible releases, or a tag (`@v1.2.0`) or a commit SHA
  to freeze. See the [changelog](CHANGELOG.md).

## Development

```bash
npm ci
npm test        # unit tests of src/core.ts (Node 24+ runs TypeScript directly)
npm run build   # bundles src/index.ts → dist/index.js (committed)
```

The Action runs the committed `dist/index.js`; CI fails if `dist/` is out of date
with `src/`. See the [API docs](https://vuln.mlab.sh/api) for the underlying endpoint.

## License

[MIT](LICENSE)
