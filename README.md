# vuln.mlab.sh SBOM scan — GitHub Action

Scan your lockfiles for known CVEs on every push or pull request, powered by
[vuln.mlab.sh](https://vuln.mlab.sh). Auto-detects lockfiles, checks every
dependency against OSV + Sonatype OSS Index, writes a job summary, and fails the
build (or just reports) based on a severity threshold.

No dependency install, no local database — parsing and scanning happen
server-side. The Action just uploads your lockfile and reports the result.

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

Anonymous scans are rate-limited to **8/hour per IP** — and GitHub-hosted runners
share egress IPs across many repos, so anonymous CI is unreliable. A personal API
token gets you a dedicated **25 scans/hour**.

1. Sign in at [vuln.mlab.sh/me/tokens](https://vuln.mlab.sh/me/tokens) and generate a token.
2. Add it as a repository secret named `VULN_MLAB_TOKEN`.
3. Pass it via the `token:` input (as above).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | *(auto-detect)* | Lockfile(s) to scan, newline- or comma-separated. |
| `working-directory` | `.` | Base directory for auto-detection. |
| `format` | `auto` | Force the parser: `npm`, `cargo`, `pip`, `composer`, `gem`, `go`, `cyclonedx`, `mise`. |
| `fail-on` | `any` | Minimum severity that fails the build: `any`, `critical`, `high`, `medium`, `low`, `none`. |
| `soft-fail` | `false` | If `true`, never fail the build — report findings and set outputs only. |
| `token` | *(none)* | vuln.mlab.sh API token. Strongly recommended for CI. |
| `api-url` | `https://vuln.mlab.sh/api/v2/scan` | Override the scan endpoint. |

**Auto-detected lockfiles:** `Cargo.lock`, `package-lock.json`,
`npm-shrinkwrap.json`, `composer.lock`, `Gemfile.lock`, `go.sum`,
`requirements.txt`, `mise.lock`. (`node_modules`, `vendor`, `target`, … are skipped.)

## Outputs

| Output | Description |
| --- | --- |
| `total` | Total vulnerabilities found across all lockfiles. |
| `vulnerable-packages` | Number of distinct vulnerable packages. |
| `failed` | `true` if the `fail-on` threshold was met (regardless of `soft-fail`). |

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

**Monorepo — scan several lockfiles:**

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

- normalizes each finding's severity,
- applies your `fail-on` threshold,
- annotates the worst offenders inline (errors for high/critical, warnings otherwise),
- writes a summary table to the job summary,
- sets the `total` / `vulnerable-packages` / `failed` outputs.

## Notes

- Coordinates the scanner couldn't resolve (upstream outage) are surfaced as
  warnings and **not** counted as clean — they never silently pass a gate.
- Manifests over 512 packages are scanned up to that ceiling (a warning is
  emitted); split very large monorepos across multiple lockfile paths.
- When scanning multiple lockfiles the Action spaces requests ~1s apart to stay
  within the per-token rate limit.

## Development

```bash
npm ci
npm run build   # bundles src/index.ts → dist/index.js (committed)
```

The Action runs the committed `dist/index.js`; CI fails if `dist/` is out of date
with `src/`. See the [API docs](https://vuln.mlab.sh/api) for the underlying endpoint.

## License

[MIT](LICENSE)
