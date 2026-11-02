import * as core from '@actions/core'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as zlib from 'node:zlib'
import {
  Finding, GateHit, KNOWN, Refusal, ScanRefused, ScanResponse, SEV_RANK, SEVERITIES, Upgrade,
  errorFor, evaluateGate, findingsOf, gateRules, intelNeeded, intelOf, isIgnored, locateLine, monitorBranch, rawUrl, scoreBadge, scoreFor, toSarif, VULN_PREDICATE_TYPE, vulnPredicate,
} from './core'
import { loadVulnYml } from './vulnYml'

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', 'target', 'dist', '.venv', 'venv'])
const ANNOTATION_LIMIT = 50

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
  if (explicit.length) return explicit.map(f => (path.isAbsolute(f) ? f : path.join(workdir, f)))
  return autoDetect(workdir)
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

// ── Talking to the API ───────────────────────────────────────────────────────
// The server spaces scans by a per-caller cooldown (10 s anonymous, 5 s on a
// free account, none on a paid plan) and states it in every response, so the
// Action learns it from the first scan and waits it out between files. A 429
// that still happens (a shared runner IP) is waited out and retried.

interface Session {
  apiUrl: string
  token: string
  format: string
  /** Seconds between two scans, as the server last stated it. */
  cooldown: number
  lastRequestAt: number
  tier?: string
  limits?: ScanResponse['limits']
  /** The first "next tier" the server pointed at, shown once in the summary. */
  upgrade?: Upgrade
}

async function requestScan(s: Session, file: string, rel: string, body: Buffer): Promise<ScanResponse> {
  const hint = s.format !== 'auto' ? s.format : (KNOWN[path.basename(file).toLowerCase()] ?? 'auto')
  const url = new URL(s.apiUrl)
  if (hint !== 'auto') url.searchParams.set('format', hint)
  url.searchParams.set('filename', path.basename(file))
  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
  if (s.token) headers['Authorization'] = `Bearer ${s.token}`

  for (let attempt = 1; ; attempt++) {
    const wait = s.lastRequestAt + s.cooldown * 1000 - Date.now()
    if (wait > 0) await sleep(wait)
    s.lastRequestAt = Date.now()

    let resp: Response
    try {
      resp = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(120_000) })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (attempt < 3) {
        core.info(`${rel}: could not reach ${url.host} (${msg}), retrying in ${5 * attempt} s`)
        await sleep(5000 * attempt)
        continue
      }
      throw new Error(`could not reach ${url.host}: ${msg}`)
    }

    if (resp.ok) {
      const data = (await resp.json()) as ScanResponse
      s.tier = data.tier ?? s.tier
      s.limits = data.limits ?? s.limits
      s.cooldown = data.limits?.cooldown_secs ?? s.cooldown
      return data
    }
    const refusal = errorFor(resp.status, (await resp.json().catch(() => undefined)) as Refusal | undefined, resp.headers.get('retry-after'), rel)
    if (refusal.kind === 'cooldown' && attempt < 4) {
      const secs = Math.min(Math.max(refusal.retryAfter ?? 10, 1), 120)
      core.info(`${rel}: scan cooldown, waiting ${secs} s`)
      await sleep(secs * 1000)
      s.lastRequestAt = 0
      continue
    }
    if (resp.status >= 500 && attempt < 3) {
      core.info(`${rel}: HTTP ${resp.status}, retrying in ${5 * attempt} s`)
      await sleep(5000 * attempt)
      continue
    }
    throw refusal
  }
}

/** What one lockfile contributed to the run. */
interface FileReport {
  file: string
  /** Packages the server scanned, and how many the manifest had (more when truncated). */
  scanned: number
  total: number
  findings: Finding[]
  /** Why this result does not cover the whole manifest (truncation, unscanned entries, outage). */
  gaps: string[]
  /** Set when the file could not be scanned at all. */
  error?: string
  text: string
}

async function scanFile(s: Session, file: string): Promise<FileReport> {
  const rel = path.relative(process.cwd(), file) || file
  const body = fs.readFileSync(file)
  const report: FileReport = { file: rel, scanned: 0, total: 0, findings: [], gaps: [], text: body.toString('utf8') }

  let data: ScanResponse
  try {
    data = await requestScan(s, file, rel, body)
  } catch (err) {
    if (err instanceof ScanRefused) {
      if (err.kind === 'auth') throw err // a configuration error: nothing else can succeed
      s.upgrade ??= err.upgrade
      if (err.kind === 'unparseable') {
        core.warning(`${rel}: ${err.message}`, { file: rel })
        return report
      }
    }
    report.error = err instanceof Error ? err.message : String(err)
    return report
  }

  const { findings, unresolved } = findingsOf(data, rel)
  report.findings = findings
  report.scanned = data.count
  report.total = data.truncation?.total_packages ?? data.count
  if (data.truncation) {
    report.gaps.push(data.truncation.message)
    s.upgrade ??= data.truncation.upgrade
  } else if (data.truncated) {
    report.gaps.push(`Only the first ${data.count} packages were scanned (scan limit); the rest are not counted as clean.`)
  }
  if (unresolved.length) {
    const why = data.outage ? 'the vulnerability database was unavailable' : 'the scanner could not query them'
    report.gaps.push(`${unresolved.length} package(s) could not be checked (${why}), not counted as clean: ${list(unresolved)}`)
  }
  if (data.unscanned?.length) {
    report.gaps.push(`${data.unscanned.length} entr${data.unscanned.length === 1 ? 'y' : 'ies'} could not be scanned (git or path dependency, unpinned version, SBOM component without purl or cpe), not counted as clean: ${list(data.unscanned)}`)
  }
  return report
}

function list(items: string[]): string {
  return items.slice(0, 10).join(', ') + (items.length > 10 ? `, and ${items.length - 10} more` : '')
}

// ── SBOM monitoring ──────────────────────────────────────────────────────────
// Registers each lockfile as a monitored project on vuln.mlab.sh (Pro plan),
// which rescans it from the branch tip and alerts on new CVEs. Known projects
// (same source URL) get a rescan instead of a duplicate. Never fails the build.

async function monitor(s: Session, files: string[], sourceToken: string): Promise<void> {
  if (!s.token) { core.warning('monitor: needs the `token` input (a vuln.mlab.sh account on a Pro plan), skipped.'); return }
  const repo = process.env.GITHUB_REPOSITORY
  let event: Parameters<typeof monitorBranch>[1]
  try { event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH ?? '', 'utf8')) } catch { event = undefined }
  const { branch, skip } = monitorBranch(process.env, event)
  if (!repo || !branch) { core.info(`monitor: skipped, ${skip ?? 'GITHUB_REPOSITORY is unset'}.`); return }
  if ((event as { repository?: { private?: boolean } })?.repository?.private && !sourceToken) {
    core.warning('monitor: the repository is private, so mlab cannot fetch its lockfiles. Set `monitor-source-token` (a read-only token for this repo), skipped.')
    return
  }

  const api = new URL('/api/v1/sbom', s.apiUrl).toString()
  const headers = { Authorization: `Bearer ${s.token}`, 'Content-Type': 'application/json' }
  const call = async (method: string, url: string, body?: object) => {
    const resp = await fetch(url, { method, headers, body: body && JSON.stringify(body), signal: AbortSignal.timeout(30_000) })
    const json = (await resp.json().catch(() => ({}))) as { message?: string; error?: string; projects?: Array<{ id: string; source_url: string }> }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}${json.message ? `: ${json.message}` : json.error ? `: ${json.error}` : ''}`)
    return json
  }

  try {
    const known = new Map(((await call('GET', api)).projects ?? []).map(p => [p.source_url, p.id]))
    const root = process.env.GITHUB_WORKSPACE || process.cwd()
    for (const file of files) {
      const rel = path.relative(root, file)
      const url = rawUrl(repo, branch, rel)
      const id = known.get(url)
      if (id) {
        await call('POST', `${api}/${encodeURIComponent(id)}/scan`)
        core.info(`monitor: ${rel} already monitored, rescan requested.`)
      } else {
        await call('POST', api, {
          name: `${repo}/${rel}`, source_url: url, format: s.format !== 'auto' ? s.format : (KNOWN[path.basename(file).toLowerCase()] ?? 'auto'),
          ...(sourceToken ? { auth_header: `Authorization: Bearer ${sourceToken}` } : {}),
        })
        core.info(`monitor: ${rel} is now monitored on vuln.mlab.sh.`)
      }
    }
  } catch (err) {
    core.warning(`monitor: could not register the SBOM on vuln.mlab.sh (${err instanceof Error ? err.message : String(err)}). Continuous monitoring is a Pro feature: https://vuln.mlab.sh/me/sbom`)
  }
}

// ── Exploitation intel ───────────────────────────────────────────────────────
// Public, unauthenticated, no scan quota; only a CVE id is sent. A lookup that
// fails leaves the finding without intel: it is reported, never a crash.

const ACTORS_ORIGIN = 'https://actors.mlab.sh'

async function getJson(url: string): Promise<unknown> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(15_000) })
    return resp.ok ? await resp.json() : undefined
  } catch {
    return undefined
  }
}

/** Attach intel to every finding with a CVE id, 6 lookups at a time. Returns the CVEs that could not be looked up. */
async function enrich(findings: Finding[], vulnOrigin: string, withActors: boolean): Promise<string[]> {
  const queue = [...new Set(findings.map(f => f.cve).filter(id => /^CVE-\d{4}-\d{4,}$/.test(id)))]
  const intel = new Map<string, ReturnType<typeof intelOf>>()
  const worker = async () => {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
      const [cve, actors] = await Promise.all([
        getJson(`${vulnOrigin}/api/v1/cve/${id}`),
        withActors ? getJson(`${ACTORS_ORIGIN}/api/v1/cves/${id}/actors`) : undefined,
      ])
      intel.set(id, intelOf(cve, actors))
    }
  }
  await Promise.all(Array.from({ length: 6 }, worker))
  for (const f of findings) f.intel = intel.get(f.cve)
  return [...intel].filter(([, v]) => !v).map(([id]) => id)
}

function exploitation(f: Finding): string {
  if (!f.intel) return ''
  const parts = [
    ...(f.intel.kev ? ['KEV'] : []),
    ...(f.intel.epss !== undefined ? [`EPSS ${(f.intel.epss * 100).toFixed(f.intel.epss >= 0.1 ? 0 : 2)}%`] : []),
    ...(f.intel.actors?.length ? [f.intel.actors.slice(0, 3).join(', ')] : []),
  ]
  return parts.join(' · ')
}

// ── Report ───────────────────────────────────────────────────────────────────

const ICON: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', unknown: '⚪' }

function limitsLine(s: Session): string | undefined {
  if (!s.limits || !s.tier) return undefined
  const who = s.tier === 'anonymous' ? 'anonymously' : `with a ${s.tier} account`
  const gap = s.limits.cooldown_secs ? `one scan every ${s.limits.cooldown_secs} s` : 'no cooldown'
  return `Scanned ${who}: up to ${s.limits.max_packages} packages per lockfile, ${gap}.`
}

function writeSummary(s: Session, all: Finding[], reports: FileReport[], counts: Record<string, number>, hits: GateHit[]) {
  const sum = core.summary.addHeading('vuln.mlab.sh SBOM scan', 2)
  sum.addRaw(all.length === 0
    ? '✅ No known vulnerabilities found.'
    : `Found **${all.length}** vulnerabilities: ` + SEVERITIES.map(sev => `${ICON[sev]} ${counts[sev]} ${sev}`).join(' · '))
    .addBreak()
  const limits = limitsLine(s)
  if (limits) sum.addRaw(limits).addBreak()

  sum.addTable([
    [{ data: 'Lockfile', header: true }, { data: 'Packages', header: true }, { data: 'Vulns', header: true }, { data: 'Coverage', header: true }],
    ...reports.map(r => [
      r.file,
      r.error ? '-' : r.scanned === r.total ? String(r.total) : `${r.scanned} of ${r.total}`,
      r.error ? '-' : String(r.findings.length),
      r.error ? '❌ not scanned' : r.gaps.length ? '⚠️ partial' : '✅ complete',
    ]),
  ])

  if (hits.length) {
    sum.addHeading('Gate', 3).addList(hits.map(h => `${h.action === 'block' ? '⛔ block' : '⚠️ warn'}: \`${h.rule}\`: ${h.reason}`))
  }

  const problems = reports.flatMap(r => [...(r.error ? [`**${r.file}** could not be scanned: ${r.error}`] : []), ...r.gaps.map(g => `**${r.file}**: ${g}`)])
  if (problems.length) {
    sum.addHeading('Not fully scanned', 3).addList(problems)
  }

  if (all.length) {
    const rows = [...all]
      .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
      .slice(0, 100)
      .map(f => [`${ICON[f.severity]} ${f.severity}`, f.pkg, f.cve, exploitation(f), f.fixed ?? '', f.file])
    sum.addTable([
      [{ data: 'Severity', header: true }, { data: 'Package', header: true }, { data: 'Advisory', header: true }, { data: 'Exploitation', header: true }, { data: 'Fixed in', header: true }, { data: 'Lockfile', header: true }],
      ...rows,
    ])
    if (all.length > 100) sum.addRaw(`…and ${all.length - 100} more.`).addBreak()
  }

  if (s.upgrade) sum.addRaw(`${s.upgrade.message} ${s.upgrade.url}`).addBreak()
}

// ── SARIF upload ─────────────────────────────────────────────────────────────

/** POST the log to Code Scanning. Needs `security-events: write`; a refusal is a warning, not a failed scan. */
async function uploadSarif(file: string, token: string): Promise<void> {
  const repo = process.env.GITHUB_REPOSITORY
  if (!repo || !process.env.GITHUB_SHA || !process.env.GITHUB_REF) {
    core.warning('upload-sarif: not running in GitHub Actions (GITHUB_REPOSITORY, GITHUB_SHA or GITHUB_REF missing), skipped.')
    return
  }
  const api = process.env.GITHUB_API_URL || 'https://api.github.com'
  const resp = await fetch(`${api}/repos/${repo}/code-scanning/sarifs`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      commit_sha: process.env.GITHUB_SHA,
      ref: process.env.GITHUB_REF,
      sarif: zlib.gzipSync(fs.readFileSync(file)).toString('base64'),
      tool_name: 'vuln.mlab.sh',
    }),
    signal: AbortSignal.timeout(60_000),
  }).catch((err: unknown) => err as Error)
  if (resp instanceof Error) { core.warning(`SARIF upload failed: ${resp.message}`); return }
  if (resp.ok) { core.info(`SARIF uploaded to Code Scanning (${repo}).`); return }
  const why = resp.status === 403 || resp.status === 404
    ? ' Check `permissions: security-events: write`, and that code scanning is enabled (GitHub Advanced Security on a private repo).'
    : ''
  core.warning(`SARIF upload refused: HTTP ${resp.status} ${(await resp.text()).slice(0, 300)}.${why}`)
}

// ── Run ──────────────────────────────────────────────────────────────────────

function setOutputs(o: Record<string, string | number | boolean>) {
  for (const [k, v] of Object.entries(o)) core.setOutput(k, String(v))
}

const EMPTY_OUTPUTS = {
  total: 0, 'vulnerable-packages': 0, failed: false, incomplete: false, 'not-scanned': 0,
  critical: 0, high: 0, medium: 0, low: 0, unknown: 0, score: 100,
}

async function run(): Promise<void> {
  const startedOn = new Date()
  const failOn = (core.getInput('fail-on') || 'any').toLowerCase()
  const failOnIncomplete = core.getInput('fail-on-incomplete') ? core.getBooleanInput('fail-on-incomplete') : false
  const workdir = core.getInput('working-directory') || '.'
  const session: Session = {
    apiUrl: core.getInput('api-url') || 'https://vuln.mlab.sh/api/v2/scan',
    token: core.getInput('token'),
    format: (core.getInput('format') || 'auto').toLowerCase(),
    cooldown: 0,
    lastRequestAt: 0,
  }

  const yml = loadVulnYml(process.cwd())
  if (yml.disable) {
    core.notice('mlab is disabled for this repository by `disable: true` in .mlab/vuln.yml. Nothing scanned.')
    setOutputs(EMPTY_OUTPUTS)
    return
  }
  const ignored = new Set(yml.ignoreVulns.map(s => s.toUpperCase()))
  const rules = gateRules(yml, failOn, failOnIncomplete)
  const softFail = core.getBooleanInput('soft-fail') || yml.notify

  const files = resolveFiles(core.getInput('path'), workdir).filter(f => {
    if (fs.existsSync(f)) return true
    core.warning(`Lockfile not found: ${f}`)
    return false
  })
  if (files.length === 0) {
    core.warning('No lockfiles found to scan. Set the `path` input or run in a repo with a supported lockfile.')
    setOutputs(EMPTY_OUTPUTS)
    return
  }
  core.info(`Scanning ${files.length} lockfile(s): ${files.map(f => path.relative(process.cwd(), f)).join(', ')}`)

  const reports: FileReport[] = []
  for (const file of files) {
    const r = await scanFile(session, file)
    const kept = r.findings.filter(f => !isIgnored(f, ignored))
    if (kept.length < r.findings.length) core.info(`${r.file}: ${r.findings.length - kept.length} finding(s) ignored by .mlab/vuln.yml`)
    r.findings = kept
    reports.push(r)
  }

  const all = reports.flatMap(r => r.findings)
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const f of all) counts[f.severity]++

  const need = intelNeeded(rules)
  if (need.cve && all.length) {
    const missing = await enrich(all, new URL(session.apiUrl).origin, need.actors)
    if (missing.length) core.warning(`Exploitation data unavailable for ${missing.length} CVE(s), not matched by kev / epss / actor rules: ${list(missing)}`)
  }

  // Annotations land on the lockfile line that declares the package, worst first.
  const texts = new Map(reports.map(r => [r.file, r.text]))
  const lineOf = (f: Finding) => locateLine(texts.get(f.file) ?? '', f.name, f.version)
  for (const f of [...all].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]).slice(0, ANNOTATION_LIMIT)) {
    const props = { file: f.file, startLine: lineOf(f), title: `${f.cve} (${f.severity})` }
    const msg = `${f.pkg}: ${f.cve}${f.fixed ? `, fixed in ${f.fixed}` : ''}${f.summary ? `. ${f.summary}` : ''}`
    if (SEV_RANK[f.severity] >= SEV_RANK.high) core.error(msg, props); else core.warning(msg, props)
  }
  if (all.length > ANNOTATION_LIMIT) core.info(`${all.length - ANNOTATION_LIMIT} more finding(s) in the job summary.`)
  for (const r of reports) {
    if (r.error) core.error(`${r.file} could not be scanned: ${r.error}`, { file: r.file })
    for (const g of r.gaps) core.warning(`${r.file}: ${g}`, { file: r.file })
  }
  if (session.upgrade) core.notice(`${session.upgrade.message} ${session.upgrade.url}`)

  const uploadSarifOn = core.getBooleanInput('upload-sarif')
  const sarifFile = core.getInput('sarif-file') || (uploadSarifOn ? path.join(process.env.RUNNER_TEMP || '.', 'mlab-vuln.sarif') : '')
  if (sarifFile) {
    fs.writeFileSync(sarifFile, JSON.stringify(toSarif(all, lineOf), null, 2))
    core.setOutput('sarif-file', sarifFile)
    if (uploadSarifOn) await uploadSarif(sarifFile, core.getInput('github-token'))
  }

  if (core.getBooleanInput('monitor')) {
    await monitor(session, files.filter((_, n) => !reports[n].error), core.getInput('monitor-source-token'))
  }

  const incomplete = reports.some(r => r.error || r.gaps.length)
  const hits = evaluateGate(rules, {
    findings: all,
    unscannedFiles: reports.filter(r => r.error).length,
    partial: reports.some(r => r.gaps.length),
  })
  writeSummary(session, all, reports, counts, hits)
  await core.summary.write()

  const badgeFile = core.getInput('badge-file')
  if (badgeFile) {
    fs.mkdirSync(path.dirname(badgeFile), { recursive: true })
    fs.writeFileSync(badgeFile, scoreBadge(all, incomplete))
    core.info(`Badge written to ${badgeFile}.`)
  }

  const predicateFile = core.getInput('attestation-predicate')
  if (predicateFile) {
    fs.mkdirSync(path.dirname(predicateFile), { recursive: true })
    fs.writeFileSync(predicateFile, JSON.stringify(vulnPredicate(all, startedOn, new Date()), null, 2))
    core.setOutput('attestation-predicate', predicateFile)
    core.setOutput('attestation-predicate-type', VULN_PREDICATE_TYPE)
  }

  const reasons = hits.filter(h => h.action === 'block').map(h => h.reason)
  for (const h of hits) if (h.action === 'warn') core.warning(`Gate (warn) ${h.rule}: ${h.reason}`)
  const failed = reasons.length > 0
  const notScanned = reports.reduce((n, r) => n + (r.total - r.scanned), 0)

  setOutputs({
    ...counts,
    total: all.length,
    'vulnerable-packages': new Set(all.map(f => f.pkg)).size,
    failed,
    incomplete,
    'not-scanned': notScanned,
    score: scoreFor(all),
  })

  const line = all.length
    ? `Found ${all.length} vulnerabilities across ${new Set(all.map(f => f.pkg)).size} package(s).`
    : 'No known vulnerabilities found.'
  if (failed && !softFail) core.setFailed(`${line} Failing: ${reasons.join('; ')}.`)
  else if (failed) core.warning(`${line} ${reasons.join('; ')} (soft-fail: not failing the build).`)
  else core.info(`${line}${all.length ? ' No block rule fired.' : ''}`)
}

run().catch(err => core.setFailed(err instanceof Error ? err.message : String(err)))
