// node --test test/*.test.ts (Node 24+ runs TypeScript by stripping types)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cveOf, errorFor, findingsOf, isIgnored, locateLine, scoreOf, severityOf, KNOWN, THRESHOLDS } from '../src/core.ts'

test('a CVSS vector is scored, not read as "unknown"', () => {
  // The bug this fixes: parseFloat("A:H") on the vector tail gave NaN.
  assert.equal(scoreOf('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8)
  assert.equal(severityOf({ severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'critical')
  assert.equal(severityOf({ severity: [{ score: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] }), 'medium')
  // database_specific wins, GitHub's "moderate" is "medium"; v2 and v4 vectors are not guessed.
  assert.equal(severityOf({ database_specific: { severity: 'MODERATE' }, severity: [{ score: '9.8' }] }), 'medium')
  assert.equal(severityOf({ severity: [{ score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }] }), 'unknown')
  assert.equal(scoreOf('7.5'), 7.5)
})

test('cveOf reads aliases, upstream and the id itself, as the server does', () => {
  assert.equal(cveOf({ id: 'GHSA-x', aliases: ['RUSTSEC-1', 'CVE-2020-26235'] }), 'CVE-2020-26235')
  assert.equal(cveOf({ id: 'DSA-5000-1', upstream: ['CVE-2023-0001'] }), 'CVE-2023-0001')
  assert.equal(cveOf({ id: 'DEBIAN-CVE-2023-5363', aliases: [] }), 'CVE-2023-5363')
  assert.equal(cveOf({ id: 'GHSA-only' }), 'GHSA-only')
})

test('one finding per package and CVE, worst severity kept, every id kept for the ignore list', () => {
  const { findings, unresolved } = findingsOf({
    hash: 'h', count: 3,
    packages: [{ name: 'time', version: '0.1.43' }, { name: 'serde', version: '1.0.100' }, { name: 'mystery', version: '2' }],
    results: [
      { ok: true, vulns: [
        { id: 'GHSA-wcg3', aliases: ['CVE-2020-26235'], severity: [{ score: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] },
        { id: 'RUSTSEC-2020-0071', aliases: ['CVE-2020-26235'], database_specific: { severity: 'HIGH' },
          affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '0.2.23' }] }] }] },
      ] },
      { ok: true, vulns: [] },
      { ok: false },
    ],
  }, 'Cargo.lock')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].severity, 'high')
  assert.equal(findings[0].fixed, '0.2.23')
  assert.deepEqual(findings[0].ids.sort(), ['CVE-2020-26235', 'GHSA-wcg3', 'RUSTSEC-2020-0071'])
  assert.deepEqual(unresolved, ['mystery@2'])
  assert.ok(isIgnored(findings[0], new Set(['RUSTSEC-2020-0071'])))
  assert.ok(!isIgnored(findings[0], new Set(['CVE-2099-0001'])))
})

const upgrade = {
  tier: 'free', max_packages: 1024, cooldown_secs: 5, url: 'https://vuln.mlab.sh/sso/login?next=/scan',
  message: 'Create a free account to scan up to 1024 packages per scan (8 MiB per request), with a 5 second cooldown.',
}

test('refusals keep the server wording and say what the next tier unlocks', () => {
  const cooldown = errorFor(429, { error: 'cooldown', retry_after_secs: 7, upgrade, message: 'Anonymous scans are limited to one every 10 seconds. Retry in 7 seconds.' }, '7', 'Cargo.lock')
  assert.equal(cooldown.kind, 'cooldown')
  assert.equal(cooldown.retryAfter, 7)
  assert.equal(cooldown.message, `Anonymous scans are limited to one every 10 seconds. Retry in 7 seconds. ${upgrade.message}`)
  assert.equal(errorFor(429, undefined, '10', 'Cargo.lock').retryAfter, 10)

  const big = errorFor(413, { error: 'payload_too_large', message: 'The request body is larger than 4 MiB, the anonymous limit.', upgrade }, null, 'bom.json')
  assert.equal(big.kind, 'too-large')
  assert.equal(big.upgrade?.tier, 'free')

  assert.equal(errorFor(401, undefined, null, 'x').kind, 'auth')
  assert.equal(errorFor(422, { error: 'no_dependencies' }, null, 'x').kind, 'unparseable')
  assert.equal(errorFor(400, { message: 'fetching the manifest returned HTTP 404' }, null, 'x').message,
    'Scan failed for x: HTTP 400: fetching the manifest returned HTTP 404')
})

test('annotations land on the declaring line', () => {
  const cargo = '# time 0.1.40 is mentioned in a comment\n[[package]]\nname = "time"\nversion = "0.1.43"\n'
  assert.equal(locateLine(cargo, 'time', '0.1.43'), 3)
  const pom = '<project>\n  <dependency>\n    <groupId>org.apache.logging.log4j</groupId>\n    <artifactId>log4j-core</artifactId>\n    <version>2.14.1</version>\n  </dependency>\n</project>'
  assert.equal(locateLine(pom, 'org.apache.logging.log4j:log4j-core', '2.14.1'), 4)
  assert.equal(locateLine('nothing here', 'left-pad', '1.0.0'), 1)
})

test('formats and thresholds', () => {
  assert.equal(KNOWN['pom.xml'], 'maven')
  assert.equal(KNOWN['pubspec.lock'], 'pub')
  assert.equal(KNOWN['bom.xml'], 'cyclonedx')
  assert.equal(THRESHOLDS.none, Infinity)
  assert.equal(THRESHOLDS.high, 3)
})
