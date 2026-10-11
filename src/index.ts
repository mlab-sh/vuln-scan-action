import * as core from '@actions/core'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { loadVulnYml } from './vulnYml'

// ── Severity model (mirrors the server's normalization) ───────────────────────
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
const THRESHOLDS: Record<string, number> = {
  any: 0, low: 1, medium: 2, high: 3, critical: 4, none: Infinity, never: Infinity,
}

/** Lockfile basenames the API can parse, mapped to a format hint. */
const KNOWN: Record<string, string> = {
  'cargo.lock': 'cargo',
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'composer.lock': 'composer',
  'gemfile.lock': 'gem',
  'go.sum': 'go',
  'requirements.txt': 'pip',
  'mise.lock': 'mise',
}
const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'target', 'dist', '.venv', 'venv'])

interface OsvVuln {
  id?: string
  aliases?: string[]
  database_specific?: { severity?: string }
  severity?: Array<{ score?: string }>
}
interface ScanResult { ok: boolean; unqueryable?: boolean; vulns?: OsvVuln[] }
interface ScanResponse {
  hash: string
  count: number
  truncated: boolean
  packages?: Array<{ ecosystem?: string; name?: string; version?: string }>
  results: ScanResult[]
}
interface Finding { file: string; pkg: string; cve: string; severity: string; ids: string[] }

function bandFromCvss(score: number): string {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'unknown'
}

function severityOf(v: OsvVuln): string {
  const ds = v.database_specific?.severity?.toLowerCase()
  if (ds) return ds === 'moderate' ? 'medium' : (SEV_RANK[ds] !== undefined ? ds : 'unknown')
  for (const s of v.severity ?? []) {
    const raw = s.score ?? ''
    const num = parseFloat(raw.includes('/') ? raw.split('/').pop()! : raw)
    if (!Number.isNaN(num)) return bandFromCvss(num)
  }
  return 'unknown'
}

function cveOf(v: OsvVuln): string {
  return v.aliases?.find(a => a.startsWith('CVE-')) ?? v.id ?? 'UNKNOWN'
}

/** Recursively collect known lockfiles under `root`, skipping vendored dirs. */
function autoDetect(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number) => {
    if (depth > 8) return
    let entries: fs.Dirent[]
    try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name), depth + 1)
      } else if (KNOWN[e.name.toLowerCase()]) {
        out.push(path.join(dir, e.name))
      }
    }
  }
  walk(root, 0)
  return out
}

function resolveFiles(input: string, workdir: string): string[] {
  const explicit = input.split(/[\n,]/).map(s => s.trim()).filter(Boolean)
  if (explicit.length) {
    return explicit.map(f => (path.isAbsolute(f) ? f : path.join(workdir, f)))
  }
  return autoDetect(workdir)
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

async function scanFile(file: string, apiUrl: string, format: string, token: string): Promise<{
  findings: Finding[]; deps: number; truncated: boolean; unscannable: number
} | null> {
  const body = fs.readFileSync(file)
  const hint = format !== 'auto' ? format : (KNOWN[path.basename(file).toLowerCase()] ?? 'auto')
  const url = new URL(apiUrl)
  if (hint !== 'auto') url.searchParams.set('format', hint)
  url.searchParams.set('filename', path.basename(file))

  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const resp = await fetch(url.toString(), { method: 'POST', headers, body })
  if (resp.status === 401) throw new Error('Invalid or revoked API token (401). Check the `token` input.')
  if (resp.status === 429) {
    const retry = resp.headers.get('retry-after') ?? '?'
    throw new Error(`Rate limited (429). Retry after ${retry}s, or use an API token for 25 scans/hour.`)
  }
  if (resp.status === 422) {
    core.warning(`No dependencies parsed from ${file} — skipping (try the \`format\` input).`)
    return { findings: [], deps: 0, truncated: false, unscannable: 0 }
  }
  if (!resp.ok) throw new Error(`Scan failed for ${file}: HTTP ${resp.status}`)

  const data = (await resp.json()) as ScanResponse
  const rel = path.relative(process.cwd(), file) || file
  const findings: Finding[] = []
  let unscannable = 0
  data.results.forEach((r, i) => {
    if (!r.ok) { unscannable++; return }
    const p = data.packages?.[i]
    const pkg = p ? `${p.name}@${p.version}` : `#${i}`
    for (const v of r.vulns ?? []) findings.push({ file: rel, pkg, cve: cveOf(v), severity: severityOf(v), ids: [v.id ?? '', ...(v.aliases ?? [])] })
  })
  if (data.truncated) core.warning(`${rel}: only the first 512 packages were scanned (manifest is larger).`)
  return { findings, deps: data.count, truncated: data.truncated, unscannable }
}

function writeSummary(all: Finding[], perFile: Array<{ file: string; deps: number; vulns: number }>) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } as Record<string, number>
  for (const f of all) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  core.summary
    .addHeading('vuln.mlab.sh SBOM scan', 2)
    .addRaw(all.length === 0
      ? '✅ No known vulnerabilities found.'
      : `Found **${all.length}** vulnerabilities — ` +
        `🔴 ${counts.critical} critical · 🟠 ${counts.high} high · 🟡 ${counts.medium} medium · 🔵 ${counts.low} low · ⚪ ${counts.unknown} unknown`)
    .addBreak()

  core.summary.addTable([
    [{ data: 'Lockfile', header: true }, { data: 'Deps', header: true }, { data: 'Vulns', header: true }],
    ...perFile.map(f => [f.file, String(f.deps), String(f.vulns)]),
  ])

  if (all.length) {
    const rows = all
      .sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
      .slice(0, 100)
      .map(f => [f.severity, f.pkg, f.cve, f.file])
    core.summary.addTable([
      [{ data: 'Severity', header: true }, { data: 'Package', header: true }, { data: 'CVE', header: true }, { data: 'Lockfile', header: true }],
      ...rows,
    ])
    if (all.length > 100) core.summary.addRaw(`…and ${all.length - 100} more.`).addBreak()
  }
}

async function run(): Promise<void> {
  const apiUrl = core.getInput('api-url') || 'https://vuln.mlab.sh/api/v2/scan'
  const format = (core.getInput('format') || 'auto').toLowerCase()
  const failOn = (core.getInput('fail-on') || 'any').toLowerCase()
  const softFail = core.getBooleanInput('soft-fail')
  const token = core.getInput('token')
  const workdir = core.getInput('working-directory') || '.'
  const threshold = THRESHOLDS[failOn] ?? 0

  const yml = loadVulnYml(process.cwd())
  if (yml.disable) {
    core.notice('mlab is disabled for this repository by `disable: true` in .mlab/vuln.yml. Nothing scanned.')
    core.setOutput('total', '0'); core.setOutput('vulnerable-packages', '0'); core.setOutput('failed', 'false')
    return
  }
  const ignored = new Set(yml.ignoreVulns.map(s => s.toUpperCase()))

  const files = resolveFiles(core.getInput('path'), workdir).filter(f => {
    if (fs.existsSync(f)) return true
    core.warning(`Lockfile not found: ${f}`)
    return false
  })

  if (files.length === 0) {
    core.warning('No lockfiles found to scan. Set the `path` input or run in a repo with a supported lockfile.')
    core.setOutput('total', '0'); core.setOutput('vulnerable-packages', '0'); core.setOutput('failed', 'false')
    return
  }
  core.info(`Scanning ${files.length} lockfile(s): ${files.map(f => path.relative(process.cwd(), f)).join(', ')}`)

  const all: Finding[] = []
  const perFile: Array<{ file: string; deps: number; vulns: number }> = []
  for (let i = 0; i < files.length; i++) {
    if (i > 0) await sleep(1100) // respect the per-token min-interval
    const rel = path.relative(process.cwd(), files[i]) || files[i]
    const res = await scanFile(files[i], apiUrl, format, token)
    if (!res) continue
    const kept = res.findings.filter(f => ![f.cve, ...f.ids].some(id => ignored.has(id.toUpperCase())))
    if (kept.length < res.findings.length) {
      core.info(`${rel}: ${res.findings.length - kept.length} finding(s) ignored by .mlab/vuln.yml`)
    }
    all.push(...kept)
    perFile.push({ file: rel, deps: res.deps, vulns: kept.length })
    if (res.unscannable > 0) core.warning(`${rel}: ${res.unscannable} coordinate(s) could not be scanned (upstream) — not counted as clean.`)
  }

  // Annotate the worst offenders inline.
  const distinctPkgs = new Set(all.map(f => f.pkg))
  for (const f of all.slice(0, 50)) {
    const msg = `${f.severity.toUpperCase()} · ${f.pkg} — ${f.cve} (${f.file})`
    if (SEV_RANK[f.severity] >= 3) core.error(msg); else core.warning(msg)
  }

  writeSummary(all, perFile)
  await core.summary.write()

  const failing = all.filter(f => (SEV_RANK[f.severity] ?? 0) >= threshold && threshold !== Infinity)
  const shouldFail = failing.length > 0

  core.setOutput('total', String(all.length))
  core.setOutput('vulnerable-packages', String(distinctPkgs.size))
  core.setOutput('failed', String(shouldFail))

  if (all.length === 0) { core.info('✅ No known vulnerabilities found.'); return }

  const line = `Found ${all.length} vulnerabilities across ${distinctPkgs.size} package(s).`
  if (shouldFail && !softFail) {
    core.setFailed(`${line} ${failing.length} at or above the '${failOn}' threshold.`)
  } else if (shouldFail && softFail) {
    core.warning(`${line} (soft-fail: not failing the build.)`)
  } else {
    core.info(`${line} None at or above the '${failOn}' threshold.`)
  }
}

run().catch(err => core.setFailed(err instanceof Error ? err.message : String(err)))
