import * as fs from 'node:fs'
import * as path from 'node:path'

// `.mlab/vuln.yml`, the same per repo file the mlab VS Code extension reads.
// The Action honours the two keys that make sense in CI:
//   disable: true       skip the scan entirely
//   ignoreVulns: [...]  advisory ids (CVE, GHSA, ...) accepted as known risk
// Other keys are editor settings and are ignored here.
//
// The parser is a copy of mlab-sh/vuln-scan-vscode src/configCore.ts, keep
// them in step.
//
// ponytail: flat `key: scalar` plus lists of scalars (block `- item` or inline
// `[a, b]`), with comments and quotes. Nested maps are ignored.

export interface VulnYml {
  disable: boolean
  ignoreVulns: string[]
}

export function loadVulnYml(root: string): VulnYml {
  let text: string
  try {
    text = fs.readFileSync(path.join(root, '.mlab', 'vuln.yml'), 'utf8')
  } catch {
    return { disable: false, ignoreVulns: [] }
  }
  const raw = parseFlatYaml(text)
  const list = typeof raw.ignoreVulns === 'string' ? [raw.ignoreVulns] : raw.ignoreVulns
  return {
    disable: raw.disable === true,
    ignoreVulns: Array.isArray(list) ? list.map(s => s.trim()).filter(Boolean) : [],
  }
}

export type YamlValue = string | number | boolean | string[]

export function parseFlatYaml(text: string): Record<string, YamlValue> {
  const out: Record<string, YamlValue> = {}
  let listKey: string | undefined
  for (const raw of text.split(/\r?\n/)) {
    if (/^\s*(#.*)?$/.test(raw)) continue
    const item = /^\s*-\s+(.*)$/.exec(raw)
    if (item && listKey) {
      const v = scalar(item[1])
      if (v !== undefined) (out[listKey] as string[]).push(String(v))
      continue
    }
    if (/^\s/.test(raw)) continue // indented, not a list item: nested map
    listKey = undefined
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(raw)
    if (!m) continue
    const [, key, rest] = m
    const inline = /^\[(.*)\]\s*(#.*)?$/.exec(rest)
    if (inline) {
      out[key] = inline[1]
        .split(',')
        .map((s) => scalar(s.trim()))
        .filter((v) => v !== undefined)
        .map(String)
      continue
    }
    const value = scalar(rest)
    if (value !== undefined) out[key] = value
    else {
      out[key] = [] // empty value: a block list may follow
      listKey = key
    }
  }
  // An empty key with nothing under it was not a list after all.
  for (const [k, v] of Object.entries(out)) if (Array.isArray(v) && v.length === 0) delete out[k]
  return out
}

function scalar(v: string): string | number | boolean | undefined {
  const quoted = /^(["'])(.*)\1\s*(#.*)?$/.exec(v)
  if (quoted) return quoted[2]
  const bare = v.replace(/\s+#.*$/, '').replace(/^#.*$/, '').trim()
  if (bare === '' || bare === '~' || bare === 'null') return undefined
  if (/^(true|yes|on)$/i.test(bare)) return true
  if (/^(false|no|off)$/i.test(bare)) return false
  if (/^-?\d+(\.\d+)?$/.test(bare)) return Number(bare)
  return bare
}
