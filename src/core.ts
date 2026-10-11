// Pure logic of the Action: no `@actions/*` import and no local import, so
// `node --test` runs it directly. index.ts does the I/O around it.
//
// The normalisation (severity, CVE, dedupe) matches the VS Code extension and
// the JetBrains plugin, so all three report the same thing for one lockfile.

// ── Lockfiles ────────────────────────────────────────────────────────────────

/** Lowercased basename to the `format` hint the API expects (vuln.mlab.sh `sbom::pick_format`). */
export const KNOWN: Record<string, string> = {
  'cargo.lock': 'cargo',
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'yarn.lock': 'yarn',
  'pnpm-lock.yaml': 'pnpm',
  'composer.lock': 'composer',
  'gemfile.lock': 'gem',
  'go.sum': 'go',
  'requirements.txt': 'pip',
  'poetry.lock': 'poetry',
  'uv.lock': 'uv',
  'pdm.lock': 'pdm',
  'pipfile.lock': 'pipfile',
  'pom.xml': 'maven',
  'gradle.lockfile': 'maven',
  'packages.lock.json': 'nuget',
  'pubspec.lock': 'pub',
  'mix.lock': 'hex',
  'mise.lock': 'mise',
  // CycloneDX SBOMs under the spec's recommended names.
  'bom.json': 'cyclonedx',
  'bom.xml': 'cyclonedx',
}

// ── API shapes ───────────────────────────────────────────────────────────────

export interface OsvVuln {
  id?: string
  aliases?: string[]
  /** CVEs a distro record (Debian, Ubuntu) is about, when `aliases` is empty. */
  upstream?: string[]
  summary?: string
  database_specific?: { severity?: string }
  severity?: Array<{ score?: string }>
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>
}

export interface Upgrade {
  tier: string
  max_packages: number
  cooldown_secs: number
  message: string
  url: string
}

export interface ScanResponse {
  hash: string
  count: number
  truncated?: boolean
  truncation?: { total_packages: number; scanned: number; not_scanned: number; message: string; upgrade?: Upgrade }
  tier?: string
  limits?: { max_packages: number; cooldown_secs: number; max_body_bytes: number }
  unscanned?: string[]
  outage?: boolean
  packages?: Array<{ ecosystem?: string; name?: string; version?: string; cpe?: string }>
  results: Array<{ ok: boolean; unqueryable?: boolean; vulns?: OsvVuln[] }>
}

/** Body of a refused scan: 429 (cooldown), 413 (too large), 422, 400, 401. */
export interface Refusal {
  error?: string
  message?: string
  retry_after_secs?: number
  upgrade?: Upgrade
}

// ── Severity ─────────────────────────────────────────────────────────────────

export const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const
export const THRESHOLDS: Record<string, number> = {
  any: 0, low: 1, medium: 2, high: 3, critical: 4, none: Infinity, never: Infinity,
}

function bandFromCvss(score: number): string {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'unknown'
}

// CVSS v3.1 base score (specification, section 8). OSV advisories very often
// carry their severity only as a vector; without scoring it they would read as
// `unknown` and slip under a `fail-on: high` gate.
const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC: Record<string, number> = { L: 0.77, H: 0.44 }
const UI: Record<string, number> = { N: 0.85, R: 0.62 }
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }

/** The spec's Roundup: integer arithmetic, not `Math.ceil` on one decimal. */
export function roundUp(input: number): number {
  const i = Math.round(input * 100000)
  if (i % 10000 === 0) return i / 100000
  return (Math.floor(i / 10000) + 1) / 10
}

/** CVSS v3.x base score from a vector, or undefined when it is not a complete v3 vector. */
export function baseScoreV3(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//i.test(vector)) return undefined
  const m: Record<string, string> = {}
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':')
    if (k && v) m[k.toUpperCase()] = v.toUpperCase()
  }
  const changed = m.S === 'C'
  const [av, ac, pr, ui, c, i, a] = [AV[m.AV], AC[m.AC], (changed ? PR_CHANGED : PR_UNCHANGED)[m.PR], UI[m.UI], CIA[m.C], CIA[m.I], CIA[m.A]]
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined) || m.S === undefined) return undefined
  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss
  if (impact <= 0) return 0
  const exploitability = 8.22 * av * ac * pr * ui
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10))
}

/** A numeric score out of `severity[].score`: a bare number, a v3 vector, or a "vector/score" tail. */
export function scoreOf(raw: string): number | undefined {
  const text = raw.trim()
  if (text === '') return undefined
  const direct = Number(text)
  if (Number.isFinite(direct)) return direct
  const vector = baseScoreV3(text)
  if (vector !== undefined) return vector
  const tail = Number(text.split('/').pop())
  return Number.isFinite(tail) ? tail : undefined
}

/** `database_specific.severity` wins (GitHub advisories); otherwise the first scoreable CVSS entry. */
export function severityOf(v: OsvVuln): string {
  const ds = v.database_specific?.severity?.toLowerCase()
  if (ds) return ds === 'moderate' ? 'medium' : SEV_RANK[ds] !== undefined ? ds : 'unknown'
  for (const s of v.severity ?? []) {
    const num = scoreOf(s.score ?? '')
    if (num !== undefined) return bandFromCvss(num)
  }
  return 'unknown'
}

/**
 * The CVE an advisory is about, the way the server picks it: an alias first,
 * then `upstream` (Debian and Ubuntu records), then one embedded in the id
 * (`DEBIAN-CVE-2024-1234`). Falls back to the advisory id.
 */
export function cveOf(v: OsvVuln): string {
  for (const s of [...(v.aliases ?? []), ...(v.upstream ?? []), v.id ?? '']) {
    const m = /CVE-\d{4}-\d{4,}/i.exec(s)
    if (m) return m[0].toUpperCase()
  }
  return v.id ?? 'UNKNOWN'
}

/** Last `fixed` event across all affected ranges. */
export function fixedVersionOf(v: OsvVuln): string | undefined {
  let fixed: string | undefined
  for (const a of v.affected ?? []) for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed = e.fixed
  return fixed
}

// ── Findings ─────────────────────────────────────────────────────────────────

export interface Finding {
  file: string
  pkg: string
  name: string
  version: string
  cve: string
  severity: string
  /** Every advisory id merged into this finding (GHSA, RUSTSEC, ...), for the ignore list. */
  ids: string[]
  fixed?: string
  summary?: string
}

/**
 * Findings of one scanned file, one per (package, CVE): the same CVE often
 * arrives as several advisories (GHSA + RUSTSEC ...), which are merged keeping
 * the worst severity. Packages the server could not scan go to `unresolved`.
 */
export function findingsOf(data: ScanResponse, file: string): { findings: Finding[]; unresolved: string[] } {
  const findings: Finding[] = []
  const unresolved: string[] = []
  data.results.forEach((r, i) => {
    const p = data.packages?.[i]
    const name = p?.name ?? `#${i}`
    const version = p?.version ?? ''
    const pkg = p?.name ? `${p.name}@${version}` : `#${i}`
    if (!r.ok) { unresolved.push(pkg); return }
    const byCve = new Map<string, Finding>()
    for (const v of r.vulns ?? []) {
      const cve = cveOf(v)
      const severity = severityOf(v)
      const ids = [v.id ?? '', ...(v.aliases ?? []), ...(v.upstream ?? [])].filter(Boolean)
      const f = byCve.get(cve)
      if (!f) {
        byCve.set(cve, { file, pkg, name, version, cve, severity, ids, fixed: fixedVersionOf(v), summary: v.summary })
        continue
      }
      if (SEV_RANK[severity] > SEV_RANK[f.severity]) f.severity = severity
      f.fixed ??= fixedVersionOf(v)
      f.summary ??= v.summary
      for (const id of ids) if (!f.ids.includes(id)) f.ids.push(id)
    }
    findings.push(...byCve.values())
  })
  return { findings, unresolved }
}

/** True when the finding (or any of its aliases) is in the ignore set (uppercased ids). */
export function isIgnored(f: Finding, ignored: Set<string>): boolean {
  return [f.cve, ...f.ids].some((id) => ignored.has(id.toUpperCase()))
}

// ── Refusals ─────────────────────────────────────────────────────────────────

export type RefusalKind = 'cooldown' | 'too-large' | 'auth' | 'unparseable' | 'http'

// Plain fields, not constructor parameter properties: Node's type stripping
// (which runs the tests) does not support those.
export class ScanRefused extends Error {
  readonly kind: RefusalKind
  /** Seconds to wait, for a cooldown. */
  readonly retryAfter?: number
  readonly upgrade?: Upgrade

  constructor(message: string, kind: RefusalKind, retryAfter?: number, upgrade?: Upgrade) {
    super(message)
    this.name = 'ScanRefused'
    this.kind = kind
    this.retryAfter = retryAfter
    this.upgrade = upgrade
  }
}

/** The error for a refused scan, in the server's own words plus what the next tier unlocks. */
export function errorFor(status: number, body: Refusal | undefined, retryHeader: string | null, file: string): ScanRefused {
  const b = body ?? {}
  const withUpgrade = (msg: string) => (b.upgrade ? `${msg} ${b.upgrade.message}` : msg)
  switch (status) {
    case 401:
      return new ScanRefused('Invalid or revoked API token (401). Check the `token` input.', 'auth')
    case 429: {
      const retry = b.retry_after_secs ?? (retryHeader !== null && Number.isFinite(Number(retryHeader)) ? Number(retryHeader) : undefined)
      return new ScanRefused(
        withUpgrade(b.message ?? `Too many scans (429).${retry !== undefined ? ` Retry in ${retry} s.` : ''}`),
        'cooldown', retry, b.upgrade,
      )
    }
    case 413:
      return new ScanRefused(withUpgrade(b.message ?? `${file} is too large to scan (413).`), 'too-large', undefined, b.upgrade)
    case 422:
      return new ScanRefused(`No dependencies parsed from ${file} (422): try the \`format\` input.`, 'unparseable')
    default:
      return new ScanRefused(`Scan failed for ${file}: HTTP ${status}${b.message ? `: ${b.message}` : '.'}`, 'http')
  }
}

// ── Where a package is declared ──────────────────────────────────────────────

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * 1-based line where `name` is declared in a lockfile, for annotations that
 * land on the diff. Formats differ too much for a parser each, so this uses
 * what they share: the name on a line, near its version. A line with the
 * version close by wins, then the first whole-token mention outside comments,
 * then line 1. A Maven `group:artifact` is looked up by its artifact, which is
 * how a pom.xml spells it.
 */
export function locateLine(text: string, name: string, version: string): number {
  const lines = text.split(/\r?\n/)
  const token = new RegExp(`(?:^|[^A-Za-z0-9_.\\-/@])${escapeRe(name)}(?:[^A-Za-z0-9_.\\-]|$)`)
  let fallback = -1
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trimStart()
    if (t.startsWith('#') || t.startsWith('//') || !token.test(lines[i])) continue
    if (version && lines.slice(i, i + 3).join('\n').includes(version)) return i + 1
    if (fallback === -1) fallback = i
  }
  if (fallback !== -1) return fallback + 1
  const colon = name.lastIndexOf(':')
  if (colon > 0) return locateLine(text, name.slice(colon + 1), version)
  return 1
}
