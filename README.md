# vuln.mlab.sh SBOM scan: GitHub Action

Scan your lockfiles and SBOMs for known CVEs on every push or pull request,
powered by [vuln.mlab.sh](https://vuln.mlab.sh). Auto-detects lockfiles, checks
every dependency against OSV and NVD, annotates the vulnerable lines in the pull
request, writes a job summary, and fails the build (or just reports) based on a
severity threshold.

No dependency install, no local database: parsing and scanning happen server
side. The Action just uploads your lockfile and reports the result.

## Quick start

```yaml
name: SBOM scan
on: [push, pull_request]

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

With no inputs, it auto-detects common lockfiles in the repo and fails on **any**
known vulnerability.

## Why a token?

| | Packages per lockfile | Request size | Cooldown between scans |
| --- | --- | --- | --- |
| Anonymous (per IP) | 512 | 4 MiB | 10 s |
| Free account, with a token | 1024 | 8 MiB | 5 s |
| Paid plan, with a token | 4096 | 32 MiB | none |

GitHub-hosted runners share egress IPs across many repositories, so an anonymous
cooldown can be taken by someone else's job. The Action waits out the cooldown
the server announces and retries, but a token is faster and steadier, and its
scans land in your history on vuln.mlab.sh.

1. Sign in at [vuln.mlab.sh/me/tokens](https://vuln.mlab.sh/me/tokens) and generate a token.
2. Add it as a repository secret named `VULN_MLAB_TOKEN`.
3. Pass it via the `token:` input (as above).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | *(auto-detect)* | Lockfile(s) or SBOM(s) to scan, newline- or comma-separated. |
| `working-directory` | `.` | Base directory for auto-detection. |
| `format` | `auto` | Force the parser: `npm`, `yarn`, `pnpm`, `cargo`, `pip`, `poetry`, `uv`, `pdm`, `pipfile`, `composer`, `gem`, `go`, `maven`, `nuget`, `pub`, `hex`, `mise`, `cyclonedx`, `spdx`. |
| `fail-on` | `any` | Minimum severity that fails the build: `any`, `critical`, `high`, `medium`, `low`, `none`. |
| `fail-on-incomplete` | `false` | If `true`, also fail when some package was not scanned (manifest over your package limit, git or path dependency, outage). Always reported either way. |
| `soft-fail` | `false` | If `true`, never fail the build: report findings and set outputs only. |
| `token` | *(none)* | vuln.mlab.sh API token. Strongly recommended for CI. |
| `api-url` | `https://vuln.mlab.sh/api/v2/scan` | Override the scan endpoint. |

**Auto-detected lockfiles:** `Cargo.lock`, `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`,
`Gemfile.lock`, `go.sum`, `requirements.txt`, `poetry.lock`, `uv.lock`,
`pdm.lock`, `Pipfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`,
`pubspec.lock`, `mix.lock`, `mise.lock`, and CycloneDX SBOMs named `bom.json` or
`bom.xml`. (`node_modules`, `vendor`, `target`, … are skipped.) Any other SBOM
(SPDX, a differently named CycloneDX file) can be passed in `path`; components
without a purl are matched by their CPE.

## `.mlab/vuln.yml`

The Action reads the same per repo file as the
[mlab VS Code extension](https://github.com/mlab-sh/vuln-scan-vscode), from the
repository root, so one file drives both the editor and CI:

```yaml
# Skip the scan entirely in this repo.
# disable: true

# Advisories accepted as known risk: not reported, never fail the build.
ignoreVulns:
  - CVE-2024-0000   # not reachable: only used in tests
  - GHSA-xxxx-xxxx-xxxx
```

Ids are matched against the advisory id and all its aliases. Other keys in the
file are editor settings and are ignored by the Action.

## Outputs

| Output | Description |
| --- | --- |
| `total` | Vulnerabilities found across all lockfiles, one per package and CVE. |
| `vulnerable-packages` | Number of distinct vulnerable packages. |
| `critical`, `high`, `medium`, `low`, `unknown` | Findings per severity. |
| `incomplete` | `true` if some package was not scanned (limit, unscannable entry, outage, or a lockfile that failed). |
| `not-scanned` | Packages left out because a manifest exceeded the package limit. |
| `failed` | `true` if the gate failed: `fail-on` threshold met, a lockfile could not be scanned, or incomplete with `fail-on-incomplete` (regardless of `soft-fail`). |

## Examples

**Report only (never fail), gate on the output yourself:**

```yaml
- id: scan
  uses: mlab-sh/vuln-scan-action@v1
  with:
    soft-fail: "true"
    token: ${{ secrets.VULN_MLAB_TOKEN }}
- run: echo "Found ${{ steps.scan.outputs.total }} vulnerabilities"
```

**Only fail on critical, scan a specific file:**

```yaml
- uses: mlab-sh/vuln-scan-action@v1
  with:
    path: server/Cargo.lock
    fail-on: critical
    token: ${{ secrets.VULN_MLAB_TOKEN }}
```

**Monorepo, scan several lockfiles:**

```yaml
- uses: mlab-sh/vuln-scan-action@v1
  with:
    path: |
      frontend/package-lock.json
      backend/go.sum
      infra/requirements.txt
    token: ${{ secrets.VULN_MLAB_TOKEN }}
```

## How it works

Each lockfile is POSTed to [`/api/v2/scan`](https://vuln.mlab.sh/api). The service
parses it, resolves every dependency's known vulnerabilities, and returns one
result per package. The Action then:

- merges the advisories that describe the same CVE (GHSA + RUSTSEC …) into one
  finding per package, keeping the worst severity,
- scores CVSS vectors when an advisory has no severity label,
- applies your `fail-on` threshold,
- annotates the worst offenders on the line of the lockfile that declares them
  (errors for high/critical, warnings otherwise),
- writes a summary to the job summary: coverage per lockfile, findings with the
  version that fixes them,
- sets the outputs.

## Notes

- Packages the scan did not cover are never counted as clean: a manifest over
  your package limit, entries the server cannot scan (git or path dependencies,
  unpinned versions, SBOM components with neither purl nor CPE), and packages
  left unchecked during an outage are listed as warnings and in the summary. Set
  `fail-on-incomplete: true` to fail the gate on them.
- A lockfile that cannot be scanned at all (over the size limit, unreachable
  server) fails the gate after the other lockfiles are scanned and reported.
- Between lockfiles the Action waits out the cooldown the server announces, and
  on a 429 waits and retries; network errors and 5xx are retried with backoff.

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
